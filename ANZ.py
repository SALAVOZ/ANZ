import argparse
import requests
import re
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Wappalyzer:
    def __init__(self, host):
        self.host = host
        self.schemas = []
        self.server = None
        self.via = None
        self.js_frameworks = []
        self.vulnerable = []

    def make_request(self, schema):
        try:
            r = requests.get(schema + '://' + self.host, verify=False, allow_redirects=True)
            try:
                if 'window.location.href' in r.text:
                    href = re.search(r'[\'\"]([\w\W]+)[\'\"]', r.text).group(1)
                    r = requests.get(schema + '://' + self.host + href, verify=False, allow_redirects=True)
            except Exception:
                pass
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
            if self.server is None:
                self.server = response.headers['Server']
            print('=' * 10)
            print('Found Server header: ' + self.server)
            print('=' * 10)
        except KeyError:
            print('=' * 10)
            print('No Server header found')
            print('=' * 10)
        try:
            self.via = response.headers['Via']
        except KeyError:
            print('=' * 10)
            print('Found Via header: ' + self.server)
            print('=' * 10)
        if 'nginx'.upper() in self.server.upper():
            self.parse_nginx_site()
        if 'apache'.upper() in self.server.upper():
            self.parse_apache_site()


    '''
    Достаём js фреймворки
    '''
    def parse_js_frameworks(self, response, schema):
        #script_tags = re.findall(r'(<script[\w\W]+?src\s*=\s*[\'\"]?([\w\W]+?)[\'\"]?[^>]*?</script>)', response.text)
        script_tags = re.findall(r'<script[\w\W]+?src=[\'\"]([\w\W]+?)[\'\"][\w\W]+?></script>', response.text)
        for script_tag in script_tags:
            self.parse_framework(script_tag, schema)

    def parse_framework(self, path, schema):
        version = None
        technologie = None
        if 'http://' in path or 'https://' in path:
            try:
                version = self.get_js_through_url(path)
            except requests.exceptions.ConnectionError:
                print('=' * 10)
                print('Error to connect to ' + path)
                print('=' * 10)
        else:
            technologie = self.get_js_technologie(path)
            version = self.get_js_through_path(path, schema, technologie)# ДОРАБОТАТЬ ФУНКЦИЮ
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

    def get_js_through_path(self, path, schema, technologie):
        try:
            url = schema + '://' + self.host + path
            res = requests.get(url, verify=False)
            if res.request.url != url:
                return None
            if res.status_code == 200:
                re_result = re.search(r'v(\d+\.\d+\.\d+)', res.request.url, re.IGNORECASE)

                if re_result is not None:
                    return re_result.group(1)

                re_result = re.search(r'\d+\.\d+\.\d+', res.text)
                if re_result is not None:
                    return re_result.group(0)

                re_result = re.search(r'VERSION\s*=\s*[\"\']?(\d+\.\d\.\d+)[\"\']?', res.text, re.IGNORECASE)
                if re_result is not None:
                    return re_result.group(1)

                re_result = re.search(fr'{technologie}\s*[=:]\s*[\"\']?(\d+\.\d\.\d+)[\"\']?', res.text, re.IGNORECASE)
                if re_result is not None:
                    return re_result.group(1)

                return None

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
                re_result = re.search(r'([-a-zA-Z0-9]+)[-.@]+', path)
                if re_result is None:
                    re_result = re.search(r'/([a-z-A-Z]+)\?', path)
                return re_result.group().replace('/', '').replace('?', '').replace('.', '')
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
                        vuln_obj = {
                            'path': fram['path'],
                            'version': fram['version'],
                            'technologie': fram['technologie'],
                            'vuln': []
                        }
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
    def snyk_condition(self, framework_version, spans):
        result_all_spans = False
        if framework_version is None:
            return None
        for span in spans:
            result_one_span = True
            version = span.text
            condition = re.findall(r'[<>=]{1,2}\d+.\d+.\d+', version)
            for condition in condition:
                if '>=' in condition:
                    result_one_span = result_one_span and (self.comparing_version(framework_version, condition.replace('>=', '')) or framework_version == condition.replace('>=', ''))
                    continue
                if '>' in condition:
                    result_one_span = result_one_span and self.comparing_version(framework_version, condition.replace('>', ''))
                    continue
                if '<=' in condition:
                    result_one_span = result_one_span and (not self.comparing_version(framework_version, condition.replace('<=','')) or framework_version == condition.replace('>=', ''))
                    continue
                if '<' in condition:
                    result_one_span = result_one_span and not self.comparing_version(framework_version, condition.replace('<',''))
                    continue
                if '=' in condition:
                    result_one_span = result_one_span and framework_version == condition.replace('=', '')
            result_all_spans = result_all_spans or result_one_span
        return result_all_spans

    def parse_nginx_site(self):
        try:
            version = re.search(r'\d+?.\d+?.\d+?', self.server).group(0)
        except Exception:
            return None
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

    def parse_apache_site(self):
        try:
            version = re.search(r'\d+.\d+.\d+', self.server).group()
        except Exception:
            print('No version on header \'Server\'')
            if self.via is None:
                return
            else:
                try:
                    version = re.search(r'\d+.\d+.\d+', self.via).group()
                except Exception:
                    return
        for i in range(11, 25, 1):
            url = f'https://httpd.apache.org/security/vulnerabilities_{i}.html'
            res = requests.get(url, verify=False)
            if res.status_code != 404:
                soup = BeautifulSoup(res.text, 'lxml')
                dls = soup.findAll('dl')
                for dl in dls:
                    dt = dl.findNext('dt')
                    dd = dl.findNext('dd')
                    cve = dt.find(text=re.compile(r'CVE-\d+-\d+'))
                    table = dd.find('table')
                    last_row = table('tr')[-1]
                    conditions = re.findall(r'\d+.\d+.\d+', last_row('td')[-1].text)
                    for condition in conditions:
                        if '>' in condition:
                            if '=' in condition and version == condition:
                                self.vulnerable.append({
                                    'Server': self.server,
                                    'vuln': cve})
                            if self.comparing_version(version, condition):
                                self.vulnerable.append({
                                    'Server': self.server,
                                    'vuln': cve})
                            continue
                        if '<' in condition:
                            if '=' in condition and version == condition:
                                self.vulnerable.append({
                                    'Server': self.server,
                                    'vuln': cve})
                            if not(self.comparing_version(version, condition)):
                                self.vulnerable.append({
                                    'Server': self.server,
                                    'vuln': cve})
                            continue
                        if version == condition:
                            self.vulnerable.append({
                                'Server': self.server,
                            'vuln': cve})

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

    def printing(self):
        without_dubls = []
        for vuln in self.vulnerable:
            if vuln not in without_dubls:
                without_dubls.append(vuln)
        for vuln in without_dubls:
            if 'Server' in vuln:
                print(vuln['Server'] + ': ' + vuln['vuln'])
            if 'path' in vuln:
                print(vuln['path'] + ' to ' + vuln['technologie'] + ' with version ' + vuln['version'] + ':' + ', '.join(vuln['vuln']))

    '''
    '''
    def run(self):
        self.get_schemas()
        self.printing()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write args: ')
    parser.add_argument('-H', '--host', type=str, required=True, help='Write host')
    args = parser.parse_args()
    Wappalyzer(args.host).run()