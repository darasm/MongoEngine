from django.db import models
from django.utils.translation import ugettext_lazy as _ 
from django.utils.encoding import smart_str
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import (
	AbstractBaseUser,
	_user_has_perm, _user_get_permissions, _user_has_module_perms,
)
from django.db import models
from django.contrib.contenttypes.models import ContentTypeManager
from django.contrib import auth

from bson.objectid import ObjectId
from mongoengine import ImproperelyConfigured

from django_mongoengine import document
from django_mongoengine import filds
from django_mongoengine.queryset import QuerySetManager
from .managers import MongoUSerManager



# Create your models here.
