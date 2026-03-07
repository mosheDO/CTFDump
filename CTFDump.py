import json
import re
import os
import sys
import codecs
import logging
from os import path
from getpass import getpass
from requests import Session
from bs4 import BeautifulSoup
from requests.utils import CaseInsensitiveDict
from urllib.parse import urlparse, urljoin
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from urllib.parse import unquote

__version__ = "0.3.0"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

class BadUserNameOrPasswordException(Exception):
    pass


class BadTokenException(Exception):
    pass


class NotLoggedInException(Exception):
    pass


class UnknownFrameworkException(Exception):
    pass


class Challenge(object):
    def __init__(self, session, url, name, category="", description="", files=None, value=0):
        self.url = url
        self.name = name
        self.value = value
        self.session = session
        self.category = category
        self.description = description
        self.logger = logging.getLogger(__name__)
        self.files = self.collect_files(files, description)

    @staticmethod
    def collect_files(files, description=""):
        files = files or []
        files.extend(re.findall(r"https?://\w+(?:\.\w+)+(?:/[\w._-]+)+", description, re.DOTALL))
        return files

    @staticmethod
    def escape_filename(filename):
        return re.sub(r"[^\w\s\-.()]", "", filename.strip())

    def print_progress(self, current, total):
        percent = (current / total) * 100
        sys.stdout.write(f"\rDownloading... {percent:.2f}%")
        sys.stdout.flush()

    def download_file(self, url, file_path):
        try:
            res = self.session.get(url, stream=True, timeout=10)
            total_size = int(res.headers.get('Content-Length', 0))
            downloaded_size = 0
            with open(file_path, 'wb') as f:
                for chunk in res.iter_content(chunk_size=1024):
                    if not chunk:
                        continue
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    self.print_progress(downloaded_size, total_size)
                print()
                f.flush()
        except Exception as ex:
            print(ex)

    def dump(self):
        # Create challenge directory if not exist
        challenge_path = path.join(
            self.escape_filename(urlparse(self.url).hostname),
            self.escape_filename(self.category),
            self.escape_filename(self.name)
        )
        os.makedirs(challenge_path, exist_ok=True)

        with codecs.open(path.join(challenge_path, "ReadMe.md"), "wb", encoding='utf-8') as f:
            f.write(f"Name: {self.name}\n")
            f.write(f"Value: {self.value}\n")
            f.write(f"Description: {self.description}\n")
            self.logger.info(f"Creating Challenge [{self.category or 'No Category'}] {self.name}")

        for file_url in self.files:
            file_path = path.join(challenge_path, self.escape_filename(path.basename(urlparse(file_url).path)))
            self.download_file(file_url, file_path)


class CTF(object):
    def __init__(self, url):
        self.url = url
        self.session = Session()
        self.logger = logging.getLogger(__name__)


    def iter_challenges(self):
        raise NotImplementedError()

    def login(self, username, password):
        raise NotImplementedError()

    def logout(self):
        self.session.get(urljoin(self.url, "/logout"))


class CTFd(CTF):
    def __init__(self, url):
        super().__init__(url)

    @property
    def version(self):
        # CTFd >= v2
        res = self.session.get(urljoin(self.url, "/api/v1/challenges"))
        if res.status_code == 403:
            # Unknown (Not logged In)
            return -1

        if res.status_code != 404:
            return 2

        # CTFd  >= v1.2
        res = self.session.get(urljoin(self.url, "/chals"))
        if res.status_code == 403:
            # Unknown (Not logged In)
            return -1

        if 'description' not in res.json()['game'][0]:
            return 1

        # CTFd  <= v1.1
        return 0

    def __get_nonce(self):
        res = self.session.get(urljoin(self.url, "/login"), headers=headers)
        html = BeautifulSoup(res.text, 'html.parser')
        return html.find("input", {'type': 'hidden', 'name': 'nonce'}).get("value")

    def login(self, username, password):
        next_url = '/challenges'
        res = self.session.post(
            url=urljoin(self.url, "/login"),
            params={'next': next_url},
            data={
                'name': username,
                'password': password,
                'nonce': self.__get_nonce()
            }
        )
        if res.ok and urlparse(res.url).path == next_url:
            return True
        return False

    def __get_file_url(self, file_name):
        if not file_name.startswith('/files/'):
            file_name = f"/files/{file_name}"
        return urljoin(self.url, file_name)

    def __iter_challenges(self):
        version = self.version
        if version < 0:
            raise NotLoggedInException()

        if version >= 2:
            res_json = self.session.get(urljoin(self.url, "/api/v1/challenges")).json()
            challenges = res_json['data']
            for challenge in challenges:
                challenge_json = self.session.get(urljoin(self.url, f"/api/v1/challenges/{challenge['id']}")).json()
                yield challenge_json['data']

            return

        res_json = self.session.get(urljoin(self.url, "/chals")).json()
        challenges = res_json['game']
        for challenge in challenges:
            if version >= 1:
                yield self.session.get(urljoin(self.url, f"/chals/{challenge['id']}")).json()
                continue

            yield challenge

    def iter_challenges(self):
        for challenge in self.__iter_challenges():
            yield Challenge(
                session=self.session, url=self.url,
                name=challenge['name'], category=challenge['category'],
                description=challenge['description'],
                files=list(map(self.__get_file_url, challenge.get('files', [])))
            )


class rCTF(CTF):
    def __init__(self, url):
        super().__init__(url)
        self.BarerToken = ''

    @staticmethod
    def __get_file_url(file_info):
        return file_info['url']

    def login(self, team_token, **kwargs):
        team_token = unquote(team_token)
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json'
        }
        res = self.session.post(
            url=urljoin(self.url, "/api/v1/auth/login"),
            headers=headers,
            data=json.dumps({
                'teamToken': team_token
            })
        )

        if res.ok:
            self.BarerToken = json.loads(res.content)['data']['authToken']
            return True
        return False

    def __iter_challenges(self):
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer {}'.format(self.BarerToken)
        }
        res_json = self.session.get(urljoin(self.url, "/api/v1/challs"), headers=headers).json()
        challenges = res_json['data']
        for challenge in challenges:
            yield challenge

    def iter_challenges(self):
        for challenge in self.__iter_challenges():
            yield Challenge(
                session=self.session, url=self.url,
                name=challenge['name'], category=challenge['category'],
                description=challenge['description'], value=challenge['points'],
                files=list(map(self.__get_file_url, challenge.get('files', [])))
            )


class itChallenge(Challenge):
    def __init__(self, session, url, name, category="", description="", files=None, value=0, files_token=None):
        super().__init__(session, url, name, category, description, files, value)
        self.files_token = files_token

    def download_file(self, url, file_path):
        headers = self.session.headers.copy()  # Start with session headers (including 'Authorization')
        if self.files_token:
             # If filesToken exists, it might be needed. 
             # However, since we don't know the exact mechanism (and filesToken is JWT),
             # we can try adding it as a query param or a specific header if the download fails?
             # Or maybe just overwrite Authorization if it's different.
             # Given the name 'filesToken', it likely replaces the session token for file operations.
             headers['Authorization'] = f"Bearer {self.files_token}"
        
        try:
            res = self.session.get(url, stream=True, headers=headers)
            res.raise_for_status()
            with open(file_path, 'wb') as f:
                for chunk in res.iter_content(chunk_size=1024):
                    if not chunk:
                        continue
                    f.write(chunk)
                f.flush()
        except Exception as ex:
            print(f"Failed to download {url}: {ex}")


class itCTF(CTF):
    def __init__(self, url):
        super().__init__(url)
        self.token = None
        self.files_token = None

    def login(self, username, password):
        headers = {
            'Content-type': 'application/json',
            'Accept': 'application/json'
        }
        try:
            res = self.session.post(
                url=urljoin(self.url, "/api/login"),
                headers=headers,
                json={'email': username, 'password': password}
            )
            
            if res.ok:
                data = res.json()
                self.token = data.get('token')
                self.files_token = data.get('filesToken')
                
                # Set default authorization for API requests
                if self.token:
                    # Clear existing auth headers just in case
                    self.session.headers.pop('Authorization', None)
                    # Add Bearer token
                    self.session.headers.update({
                        'Authorization': f"Bearer {self.token}"
                    })
                return True
        except Exception as e:
            self.logger.error(f"Login failed: {e}")
        return False

    def __iter_challenges(self):
        # Fetch structure
        try:
            res = self.session.get(urljoin(self.url, "/api/challenges?noFreeze=false"))
            if not res.ok:
                print(f"Failed to fetch challenges list: {res.status_code}")
                return

            data = res.json()
            events = data.get('events', [])
            for event in events:
                sections = event.get('sections', [])
                for section in sections:
                    challenges = section.get('challenges', [])
                    for challenge_meta in challenges:
                        challenge_id = challenge_meta.get('id')
                        try:
                            # Fetch full challenge details
                            chal_res = self.session.get(urljoin(self.url, f"/api/challenges/{challenge_id}"))
                            if chal_res.ok:
                                yield chal_res.json()
                        except Exception as e:
                            print(f"Error fetching challenge details for {challenge_id}: {e}")
        except Exception as e:
            print(f"Error iterating challenges: {e}")

    def iter_challenges(self):
        for challenge in self.__iter_challenges():
            file_urls = []
            files = challenge.get('files') or []
            if files:
                for f in files:
                    # Handle dict format: {"url": "...", "name": "..."}
                    if isinstance(f, dict):
                        f_url = f.get('url')
                        if f_url:
                            if not f_url.startswith('http'):
                                f_url = urljoin(self.url, f_url)
                            file_urls.append(f_url)
                    elif isinstance(f, str):
                        # Handle string format if any
                        f_url = f
                        if not f_url.startswith('http'):
                            f_url = urljoin(self.url, f_url)
                        file_urls.append(f_url)
            
            category = 'Unknown'
            start_cat = challenge.get('tags')
            if start_cat and len(start_cat) > 0:
                category = start_cat[0]
            
            yield itChallenge(
                session=self.session, 
                url=self.url,
                name=challenge.get('title', 'Untitled'), 
                category=category,
                description=challenge.get('description', ''), 
                value=challenge.get('currentScore', 0),
                files=file_urls,
                files_token=self.files_token
            )


class CTFsd(CTFd):
    def __init__(self, url):
        super().__init__(url)


def get_credentials(username=None, password=None):
    username = username or os.environ.get('CTF_USERNAME', input('User/Email: '))
    password = password or os.environ.get('CTF_PASSWORD', getpass('Password: ', stream=False))

    return username, password


CTFs = CaseInsensitiveDict(data={
    "CTFd": CTFd,
    "rCTF": rCTF,
    "itCTF": itCTF,
    "CTFsd": CTFsd
})


def main(args=None):
    if args is None:
        args = sys.argv[1:]

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version="%(prog)s {ver}".format(ver=__version__))

    parser.add_argument("url",
                        help="ctf url (for example: https://demo.ctfd.io/)")
    parser.add_argument("-c", "--ctf-platform",
                        choices=CTFs,
                        help="ctf platform",
                        default="CTFd")
    parser.add_argument("-n", "--no-login",
                        action="store_true",
                        help="login is not needed")
    parser.add_argument("-u", "--username",
                        help="username")
    parser.add_argument("-p", "--password",
                        help="password")
    parser.add_argument("-t", "--token",
                        help="team token for rCTF")
    sys_args = vars(parser.parse_args(args=args))

    # Configure Logger
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s',
                        datefmt='%d-%m-%y %H:%M:%S')

    ctf = CTFs.get(sys_args['ctf_platform'])(sys_args['url'])
    if sys_args['ctf_platform'] == 'rCTF':
        if not ctf.login(sys_args['token']):
            raise BadTokenException()
    elif not sys_args['no_login'] or not os.environ.get('CTF_NO_LOGIN'):
        if not ctf.login(*get_credentials(sys_args['username'], sys_args['password'])):
            raise BadUserNameOrPasswordException()

    for challenge in ctf.iter_challenges():
        challenge.dump()

    if not sys_args['no_login'] or not os.environ.get('CTF_NO_LOGIN'):
        ctf.logout()


if __name__ == '__main__':
    main()
