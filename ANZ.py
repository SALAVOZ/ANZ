import argparse
import requests
import re
from bs4 import BeautifulSoup


class Wappalyzer:
    def __init__(self, host):
        self.host = host
        self.schemas = []
        self.server = None
        self.js_frameworks = []
        self.vulnerable = []

    def make_request(self, schema):
        try:
            r = requests.get(schema + '://' + self.host, verify=False)
            return r
        except requests.exceptions.ConnectionError:
            print('=' * 10)
            print('Error to connect to ' + schema + '://' + self.host)
            print('=' * 10)
            return None

    def get_schemas(self):
        for schema in ['http','https']: # ПОТОМ СДЕЛАТЬ for schema in ['http', 'https']:
            response = self.make_request(schema)
            if response is not None:
                self.schemas.append(schema)
                self.parse_server(response)
                self.parse_js_frameworks(response, schema)
                self.parse_snyk()
        print('Found schemas: ' + ', '.join(self.schemas))

    def parse_server(self, response):
        try:
            self.server = response.headers['Server']
            if 'nginx'.upper() in self.server.upper():
                self.parse_nginx_site()
            print('=' * 10)
            print('Found Server header: ' + self.server)
            print('=' * 10)
        except KeyError:
            print('=' * 10)
            print('No Server header found')
            print('=' * 10)

    '''
    Достаём js фреймворки
    '''
    def parse_js_frameworks(self, response, schema):
        script_tags = re.findall(r'(<script\s+src\s*=\s*[\'\"]?([\w\W]+?)[\'\"]?[^>]*?</script>)', response.text)
        for script_tag in script_tags:
            tag = script_tag[1][:-2]
            self.parse_framework(tag, schema)

    def parse_framework(self, path, schema):
        version = None
        if 'http://' in path or 'https://' in path:
            try:
                version = self.get_js_through_url(path)
            except requests.exceptions.ConnectionError:
                print('=' * 10)
                print('Error to connect to ' + path)
                print('=' * 10)
        else:
            version = self.get_js_through_path(path, schema)# ДОРАБОТАТЬ ФУНКЦИЮ
        technologie = self.get_js_technologie(path)
        self.js_frameworks.append({
            'path': path,
            'version': version,
            'technologie': technologie
            })

    @staticmethod
    def get_js_through_url(url):
        try:
            res = requests.get(url, verify=False)
            re_result = re.search(r'\d+?.\d+?.\d+?', res.request.url)
            if re_result is not None:
                return re_result.group()
            re_result = re.search(r'v\d+?.\d+?.\d+?', res.text)
            if re_result is not None:
                return re_result.group()
        except requests.exceptions.ConnectionError:
            print('=' * 10)
            print('No Server header found')
            print('=' * 10)

    def get_js_through_path(self, path, schema):
        try:
            res = requests.get(schema + '://' + self.host + '/' + path, verify=False)
            if res.status_code == 200:
                re_result = re.search(r'\d+?.\d+?.\d+?', res.request.url)
                if re_result is not None:
                    return re_result.group()
                re_result = re.search(r'v\d+?.\d+?.\d+?', res.text)
                if re_result is not None:
                    return re_result.group()
        except requests.exceptions.ConnectionError:
            print('=' * 10)
            print('Connection error: ' + schema + '://' + self.host + path)
            print('=' * 10)

    @staticmethod
    def get_js_technologie(path):
        try:
            if 'http://' in path or 'https://' in path:
                return None
            else:
                re_result = re.search(r'([a-zA-Z0-9]+)[-.@]+', path)
                return re_result.group(1) # под индеком ноль почему-то re возвращает весь найденный
        except AttributeError:
            print('Error in get_js_technologie')

    # СДЕЛАТЬ ПОЛУЧЕНИЕ ВЕРСИЙ ГДЕ @
    '''
    Накидываем CVE
    '''
    def parse_snyk(self):
        for fram in self.js_frameworks:
            if fram['technologie'] is not None and fram['version'] is not None:
                tech = fram['technologie']
                res = requests.get(f'https://security.snyk.io/package/npm/{tech}', verify=False)
                soup = BeautifulSoup(res.text, 'lxml')
                table = soup.find('table', {'id': 'sortable-table'})
                if table is None:
                    continue
                trs = table.find_all('tr',class_='vue--table__row')
                #spans = table.find_all('span',class_='vue--chip__value')
                for tr in trs:
                    spans = tr.find_all('span', class_='vue--chip__value')
                    result = self.snyk_condition(fram['version'].replace('v', ''), spans)
                    if result:
                        vuln_obj = fram
                        vuln_obj['vuln'] = []
                        a = tr.find('a')['href']
                        res = requests.get(f'https://security.snyk.io/{a}')
                        soup = BeautifulSoup(res.text, 'lxml')
                        div = soup.find('div', class_='vuln-info-block')
                        spans = div.find_all('span')
                        for span in spans:
                            try:
                                vuln = span.find('span').find('a').text
                                vuln = re.search('([-WCVE0-9]+?\s*?\n)', vuln).group().replace('\n', '')
                                vuln_obj['vuln'].append(vuln)
                            except BaseException:
                                continue
                        self.vulnerable.append(vuln_obj)
    '''
    Уязвимо или нет
    '''
    @staticmethod
    def snyk_condition(framework_version, spans):
        result_all_spans = False
        if framework_version is None:
            return None
        for span in spans:
            result_one_span = True
            version = span.text
            condition = re.findall(r'[<>=]{1,2}\d+.\d+.\d+', version)
            for condition in condition:
                if '>=' in condition:
                    if framework_version >= condition.replace('=', '').replace('>', '').replace('<', ''):
                        result_one_span = result_one_span and True
                        continue
                    else:
                        result_one_span = result_one_span and False
                        continue
                if '>' in condition:
                    if framework_version > condition.replace('=', '').replace('>', '').replace('<', ''):
                        result_one_span = result_one_span and True
                        continue
                    else:
                        result_one_span = result_one_span and False
                        continue
                if '<=' in condition:
                    if framework_version <= condition.replace('=', '').replace('>', '').replace('<', ''):
                        result_one_span = result_one_span and True
                        continue
                    else:
                        result_one_span = result_one_span and False
                        continue
                if '<' in condition:
                    if framework_version < condition.replace('=', '').replace('>', '').replace('<', ''):
                        result_one_span = result_one_span and True
                        continue
                    else:
                        result_one_span = result_one_span and False
                        continue
                if '=' in condition:
                    if framework_version == condition.replace('=', '').replace('>', '').replace('<', ''):
                        result_one_span = result_one_span and True
                        continue
                    else:
                        result_one_span = result_one_span and False
                        continue
            result_all_spans = result_all_spans or result_one_span
        return result_all_spans

    def parse_nginx_site(self):
        version = re.search(r'\d+?.\d+?.\d+?', self.server).group(0)
        url = 'http://nginx.org/en/security_advisories.html'
        res = requests.get(url, verify=False)
        soup = BeautifulSoup(res.text, 'lxml')
        div = soup.find('div', {'id': 'content'})
        all_li = div.find_all('li')
        for li in all_li:
            text = li.find(text=re.compile(r'Vulnerable:[\w\W]+'))
            conditions = re.findall(r'\d+.\d+.\d+\s*-\s*\d+.\d+.\d+', text)
            for condition in conditions:
                conds = condition.replace(' ', '').split('-')
                if not(self.comparing_version(conds[0], version)) and self.comparing_version(conds[1], version):
                    try:
                        cve = li.find('a', text=re.compile(r'CVE-\d+-\d+')).text
                        self.vulnerable.append({
                            'Server': self.server,
                            'vuln': cve
                        })
                    except Exception:
                        print('Vuln at parsing nginx site')


    '''
    Вернёт True, если version > comparing
    Иначе False
    '''
    @staticmethod
    def comparing_version(version, comparing):
        version_splited = version.split('.')
        comparing_splited = comparing.split('.')
        if len(version_splited) == len(comparing_splited):
            for i in range(len(version_splited)):
                try:
                    if int(version_splited[i]) > int(comparing_splited[i]):
                        return True
                    if int(version_splited[i]) == int(comparing_splited[i]):
                        continue
                    if int(version_splited[i]) < int(comparing_splited[i]):
                        return False
                except Exception:
                    print('Error in comparing version')
        print('Error in comparing. Not equal length of args')
        return False

    '''
    '''
    def run(self):
        self.get_schemas()
        print(self.vulnerable)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write args: ')
    parser.add_argument('-H', '--host', type=str, required=True, help='Write host')
    args = parser.parse_args()
    Wappalyzer(args.host).run()