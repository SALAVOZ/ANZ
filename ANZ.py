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
        self.urls = []
        self.dict = []
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
                    self.urls.append(r.url)
            except requests.exceptions.ConnectionError:
                continue

    '''
    Получаем из сайта все теги script
    '''
    def get_js_paths(self, response):
        paths = []
        text = response.text
        scripts = re.findall(r'(<script\s+src.*?>[\w\W]*?</script>)', text, re.MULTILINE)
        return scripts


    '''
    сделать запрос и к js файлам
    '''
    def get_js_versions(self, url, tags):
        for tag in tags:
            path = re.search(r'src\s*=\s*([^>]+)', tag)
            print(path.groups())
            built_url = self.build_url_to_get_js_file(url, path.groups()[0].replace('\"', '').replace('\'', ''))
            version = self.analyze_js_file(built_url)
            self.dict.append([path.groups()[0], version])
        print(self.dict)
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
    def analyze_js_file(self, url):
        try:
            response_text = requests.get(url, verify=False).text
            version = re.search(r'(v\d+.\d+.\d+)', response_text).groups()
            print(version)
        except AttributeError:
            version = None
        return  version

    def build_url_to_get_js_file(self, url, path):
        return (url + path)

    def make_request(self, url):
        r = requests.get(url, verify=False)# Ставим verify=False, чтобы не было проблем с HTTPS
        return r

    def wappalyzer(self):
        self.get_protocols(self.ip)
        for url in self.urls:
            if url is None:
                continue
            response = self.make_request(url)
            tags = self.get_js_paths(response)
            self.get_js_versions(url, tags)
        return




if __name__ == '__main__':
    Wappalyzer('rq.tatneft.ru').wappalyzer()