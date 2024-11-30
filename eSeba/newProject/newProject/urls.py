from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    
    #admin and basic urls
    path('admin/', admin.site.urls),
    path("", include('myApp.urls'))
]
