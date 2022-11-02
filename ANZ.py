import argparse

import requests
import re

class Wappalyzer:
    def __init__(self, host):
        self.host = host
        self.schemas = []
        self.server = None
        self.js_frameworks = []
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
        for schema in ['http', 'https']:
            response = self.make_request(schema)
            if response is not None:
                self.schemas.append(schema)
                self.parse_server(response)
                self.parse_js_frameworks(response, schema)
        print('Found schemas: ' + ', '.join(self.schemas))

    def parse_server(self, response):
        try:
            self.server = response.headers['Server']
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
        if 'http://' in path or 'https://' in path:
            try:
                version = self.get_js_through_url(path)
            except requests.exceptions.ConnectionError:
                print('=' * 10)
                print('Error to connect to ' + path)
                print('=' * 10)
        else:
            version = self.get_js_through_path(path, schema)# ДОРАБОТАТЬ ФУНКЦИЮ
        self.js_frameworks.append({
            'path': path,
            'version': version,
            'technologie': ''
            })

    def get_js_through_url(self, url):
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


    def get_js_technologie(self, res):
        re_result = re.search(r'/[\w\W]+?.js', res.request.url)
        print(re_result)


    '''
    Накидываем CVE
    '''
    def parse_snyk(self):
        pass
    '''
    '''
    def run(self):
        self.get_schemas()
        print(self.js_frameworks)

'''
class Wappalyzer:
    def __init__(self, ip):
        self.ip = ip
        self.https = True
        self.http = True
    def get_protocols(self, ip):
        protocols = ['http', 'https']
        list = []
        for protocol in protocols:
            try:
                r = requests.get(protocol + '://' + ip, verify=False)
                if r.status_code == 200:
                    list.append(r)
            except requests.exceptions.ConnectionError:
                list.append(None)
                if protocol == 'http':
                    self.http = False
                if protocol == 'https':
                    self.https = False
                continue
        http_url = list[0]
        https_url = list[1]
        return http_url, https_url.url


    def get_js_paths(self, response):
        paths = []
        text = response.text
        indexs = []
        n = 1
        while True:
            r = find_nth_occurence_in_string(text, 'script src=\"', n)
            n += 1
            if r != -1:
                indexs.append(r)
            else:
                break
        for index in indexs:
            i = index
            while text[i] != '\"':
                i += 1
            j = i + 1
            while text[j] != '\"':
                j += 1
            paths.append(text[i:j].replace('\'', '').replace('\"', ''))
        return paths


    def build_url_to_get_js(self, list_of_paths):
        list = []
        if self.http:
            for path in list_of_paths:
                if 'https://' in path or 'http://' in path:
                    list.append(path)
                    continue
                list.append('http://' + self.ip + '/' + path)

        if self.https:
            for path in list_of_paths:
                if 'https://' in path or 'http://' in path:
                    list.append(path)
                    continue
                list.append('https://' + self.ip + '/' + path)
        return list

    def get_js_versions(self, urls):
        js = []
        for url in urls:
            res = requests.get(url, verify=False)
            if not(self.ip in res.url):
                result = self.analyze_js_file(res.url.split('/')[-1], res.text)
                if result:
                    js.append()
                continue
            framework = res.url.split(self.ip)[1]
            if '/' in res.url:
                result = self.analyze_js_file(framework.replace('js', '').replace('/', ''), res.text)
            else:
                result = self.analyze_js_file(framework, res.text)
            if result:
                js.append(result)
        return js


    Анализируем данный js файл на наличие версии(из названия файла и из содержимого файла)
    axios.mim.js
    vue.js
    sweetalert2@9.js
    jquery-3.2.1.min.js
    bootstrap/jquery.min.js
    signln.js?version=15
    fontawesome/all.js

    def analyze_js_file(self, name, text):
        version = re.search('[0-9].[0-9].[0-9]', name)
        if version:
            return {'name': name, 'version': version}
        version = re.search('v[0-9].[0-9]', text)
        if version:
            return {'name': name, 'version': version}
        version = re.search('v[0-9].[0-9].[0-9]', text)
        if version:
            return {'name': name, 'version': version}


    def make_request(self, url):
        r = requests.get(url, verify=False)# Ставим verify=False, чтобы не было проблем с HTTPS
        return r

    def wappalyzer(self):
        http_url, https_url = self.get_protocols(self.ip)
        for url in [http_url, https_url]:
            if url is None:
                continue
            self.get_js_versions(self.build_url_to_get_js(self.get_js_paths(self.make_request(url))))
        return

'''


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Write args: ')
    parser.add_argument('-H', '--host', type=str, required=True, help='Write host')
    args = parser.parse_args()
    Wappalyzer(args.host).run()