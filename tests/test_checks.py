import unittest
from unittest.mock import Mock
from bs4 import BeautifulSoup
from backend.scanner.checks import check_headers,check_transport,check_server,check_sri

def ctx(url="http://localhost:3000",headers=None,html="<html></html>"):
    r=Mock(); r.headers=headers or {}; r.text=html; r.url=url
    return {"response":r,"url":url,"soup":BeautifulSoup(html,"html.parser"),"session":Mock(),"timeout":2}

class TestChecks(unittest.TestCase):
    def test_headers(self):
        titles={x.title for x in check_headers(ctx())}
        self.assertIn("Missing Content-Security-Policy",titles)
        self.assertIn("Missing X-Frame-Options",titles)
    def test_transport(self):
        self.assertTrue(check_transport(ctx("http://localhost:3000")))
    def test_server(self):
        fs=check_server(ctx(headers={"Server":"Example/1.2"}))
        self.assertEqual(len(fs),1)
    def test_sri(self):
        html='<script src="https://cdn.example.invalid/app.js"></script>'
        self.assertEqual(len(check_sri(ctx(html=html))),1)

if __name__=="__main__": unittest.main()
