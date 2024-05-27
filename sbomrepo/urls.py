"""
URL configuration for sbomrepo project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from django.views.decorators.http import require_GET

from sbomrepo import views

urlpatterns = [
    path("", views.index),
    path("admin/", admin.site.urls),
    path("v1/sbom", views.SBOMView.as_view()),
    path("v1/sbom/all", views.list_sboms),
    path("v1/sbom/delete", views.delete_sboms),
    path("v1/sbom/<str:serial_number>/reimport", views.reimport_sbom),
    path("v1/sbom/<str:serial_number>", views.SBOMView.as_view()),
    path("v1/vulnerability/<str:id>", views.get_vulnerability),
    path("v1/ecosystems", views.get_ecosystems),
]

if getattr(settings, "DEBUG_TOOLBAR", False): 
    urlpatterns.append(path("__debug__/", include("debug_toolbar.urls")))
