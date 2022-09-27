import requests
import re
'''
Найти n-ое вхождение подстроки в строке
'''


def find_nth_occurence_in_string(haystack, needle, n):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start + len(needle))
        n -= 1
    return start



class Wappalyzer:
    def __init__(self, ip):
        self.ip = ip
        self.https = True
        self.http = True
    '''
    Определяет, есть ли http или https
    Возвращает две ссылки
    '''
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


    '''
    Получаем из сайта все пути к js файлам
    '''
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


    '''
    построим пути к js фремворкам
    '''
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

    '''
    сделать запрос и к js файлам
    '''
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
        return

    '''
    Анализируем данный js файл на наличие версии(из названия файла и из содержимого файла)
    axios.mim.js
    vue.js
    sweetalert2@9.js
    jquery-3.2.1.min.js
    bootstrap/jquery.min.js
    signln.js?version=15
    fontawesome/all.js
    '''
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




if __name__ == '__main__':
    Wappalyzer('rq.tatneft.ru').wappalyzer()