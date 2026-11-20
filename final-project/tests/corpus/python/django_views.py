"""Planted vulnerabilities in Django-style views (function views, a class view, URL map)."""

import os
import pickle
import subprocess

from django.db import connection
from django.http import HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from .models import User


def search(request):
    q = request.GET.get("q", "")
    rows = User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % q)  # VULN: CWE-89
    return HttpResponse(str(list(rows)))


@csrf_exempt
def export(request):
    fmt = request.POST["fmt"]
    out = subprocess.check_output("convert report.pdf " + fmt, shell=True)  # VULN: CWE-78
    return HttpResponse(out)


def by_name(request):
    sql = "SELECT * FROM auth_user WHERE username = '{}'".format(request.GET["n"])
    with connection.cursor() as cursor:
        cursor.execute(sql)  # VULN: CWE-89 regex-miss
        return HttpResponse(str(cursor.fetchall()))


class ProfileView(View):
    def post(self, request):
        profile = pickle.loads(request.body)  # VULN: CWE-502
        return HttpResponse(str(profile))

    def get(self, request):
        return HttpResponse("profile")


def ping(request, host):
    # only referenced from django_urls.py: ``path("ping/<host>/", views.ping)``
    return HttpResponse(os.popen("ping -c 1 " + host).read())  # VULN: CWE-78


class Runner:
    """Attribute flow across methods: a documented gap (not field-sensitive)."""

    def configure(self, request):
        self.command = request.GET["cmd"]

    def run(self):
        return os.system(self.command)  # VULN: CWE-78 known-gap
