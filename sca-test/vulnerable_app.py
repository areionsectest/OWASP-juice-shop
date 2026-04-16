"""
SCA test file — intentionally uses outdated packages with known CVEs.
For security testing purposes only.
"""

import requests          # pinned to 2.18.4 — CVE-2018-18074 (credentials leak via redirect)
import flask             # pinned to 0.12.2 — CVE-2018-1000656 (DoS via JSON)
import jinja2            # pinned to 2.10   — CVE-2019-10906 (sandbox escape)
import PyYAML            # pinned to 3.13   — CVE-2017-18342 (arbitrary code exec via load())
import urllib3           # pinned to 1.22   — CVE-2018-20060 (header injection)
import cryptography      # pinned to 2.1.4  — CVE-2018-10903 (weak IV in Fernet)
import paramiko          # pinned to 2.4.1  — CVE-2018-1000805 (auth bypass)


def fetch_url(url):
    # uses requests 2.18.4 — does not strip Authorization header on redirect
    response = requests.get(url, allow_redirects=True)
    return response.text


def parse_yaml(data):
    # uses PyYAML 3.13 yaml.load() without Loader — arbitrary code execution
    return yaml.load(data)


def render_template(user_input):
    env = jinja2.Environment()
    # uses jinja2 2.10 — sandbox escape possible
    template = env.from_string("Hello, " + user_input)
    return template.render()


app = flask.Flask(__name__)

@app.route("/greet")
def greet():
    name = flask.request.args.get("name", "world")
    # flask 0.12.2 — vulnerable to DoS via large JSON body
    return render_template(name)


if __name__ == "__main__":
    app.run(debug=True)
