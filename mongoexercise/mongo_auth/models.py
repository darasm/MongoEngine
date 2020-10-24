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

from random import random



# Create your models here.
def ct_init(self, *args, **kwargs):
	super(QuerySetManager, self).__init__(*args, **kwargs)
	self._cache = {}


ContentTypeManager = type(
	"ContentTypeManager",
	(QuerySetManager,),
	dict(
		ContentTypeManager.__dict__,
		__init__=ct_init,

	),
)

try:
	from django.contrib.auth.hashers import make_password, check_password
except ImportError:
	"""Lida com versoes antigas do Django"""
	from django.utils.hashcompat import md5_constructor, sha_constructor


	def get_hexdigest(algorithm, salt, raw_password):
		raw_password, salt = smart_str(raw_password), smart_str(salt)
		if algorithm == 'md5':
			return md5_constructor(salt + raw_password).hexdigest()
		elif algorithm == 'sha1':
			return sha_constructor(salt + raw_password).hexdigest()
		raise ValueError('Algoritmo não reconhecido')

	def check_password(raw_password, password):
		algo, salt, hash_ = password.split('$')
		return hash_ == get_hexdigest(algo, salt, raw_password)

	def make_password(raw_password):
		algo = 'sha1'
		salt = get_hexdigest(algo, str(random()), str(random()))[:5]
		hash_ = get_hexdigest(algo, salt, raw_password)
		return '%s$%s$%s' % (algo, salt, hash_)


class BaseUser(object):
		
	is_anonymous = AbstractBaseUser.__dict__['is_anonymous']
	is_authenticated  = AbstractBaseUser.__dict__['is_authenticated']

	@classmethod
	def get_email_field_name(cls):
		try:
			return cls.EMAIL_FIELD
		except AttributeError:
			return 'email'
		
	
class ContentType(document.Document):
	name = fields.StringField(max_length=100)
	app_label = fiels.StringField(max_length=100)
	model = fiels.StringField(max_length=100, verbose_name=_('python model class name'),
		unique_with='app_label')
	objects = ContentTypeManager()

	#Classe Meta é a classe da classe.
	class Meta:
		verbose_name = _('content type')
		verbose_name_plural = _('content types')

		def __unicode__(self):
			return self.name 

			
		def model_class(self):
			"""Retorna a classe Modle para esse tupo de contexto"""
			return models.get_model(self.app_label, self.model)

		def get_object_for_this_type(self, **kwargs):
			"""Retorna um objeto desse tipo para os argumentos de palavra-chave
				fornecidos. A exceção ObjectNotExist, se lançada, não será detectada,
				então o código que chama este método deve pegá-lo"""
			return self.model_class()._default_manager.using(self._state.db).get(**kwargs)


		def natural_key(self):
			return (self.app_label, self.model)


class SiteProfileNotActivailable(Exeption):
	pass


class PermissionManager(QuerySetManager):
	def get_by_natural_key(self, codename, app_label, model):
		return self.get(
			codename=codename,
			content_type=ContentType.objects.get_by_natural_key(app_label, model)
		)



class Permission(document.Document):
	"""O sistema de permissões permite dar permissóes diferentes para usuários
	ou grupo de usuários."""

	name = fiels.StringField(max_length=50, verbose_name=_('username'))
	content_type = fields.ReferenceField(ContentType)
	codename = fields.StringField(max_length=100, verbose_name=_('codename'))

	objects = PermissionManager()

	class Meta:
		verbose_name = _('permission')
		verbose_name_plural = _('permissions')


	def __unicode__(self):
		return u"%s | %s | %s" % (
			self.content_type.app_label
			self.content_type
			self.name,
		)

	def natural_key(self):
		return (self.codename,) + self.content_type.natural_key()
	natural_key.dependencies = ['contenttypes.contenttype']



class Group(document.Document):
	name = fields.StringField(max_length=80, unique=True, verbose_name=_('name'))
	permissions = filds.ListField(filds.ReferenceField(Permission, verbose_name=_('permissions')))

	class Meta:
		verbose_name = _('group')
		verbose_name_plural = _('groups')


class AbstractUser(BaseUser, document.Document):
	"""Um  documento User que permite o espelhamento da maioria das API especificadas
	pelo Django em: http://docs.djangoproject.com/en/dev/topics/auth/#users """

	username = fiels.StringField(

	)
