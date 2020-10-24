from django.conf import settings
from django.contrib.auth.models import UserManager
import django.db.models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _ 
from mongoengine.error import DoesNotExist 

MONGOENGINE_USER_DOCUMENT = getattr(
	settings, 'MONGOENGINE_USER_DOCUMENT', 'django_mongoengine.mongo_auth.models.user')


def get_user_document():
	"""
	Classe usada para autenticação para pegar os documentos do usuário
	"""

	name = MONGOENGINE_USER_DOCUMENT
	dot = name.rindex('.')
	module = import_module(name[:dot])
	return getattr(module, name[dot + 1:])


class MongoUserManager(UserManager):
	"""Para usar o gerenciador, agt tem que dizer ao django.contrib.auth para usar
	o MongoUser como o modelo usuário. No settings.py agt precisa:

	INSTALLED_APPS = (
		...
		'django.contrib.auth',
		'django_mongoengine.mongo_auth',
		...
	)
	AUTH_USER_MODEL = 'mongo_auth.MongoUser'

	Django vai usar o objeto model para acessar o Gerenciador personalizaso, no qual
	substituirá o quaryset original pelo quaeyset do MongoEngine.

	"""

	def contribute_to_class(self, model, name):
		super(MongoUserManager, self).contribute_to_class(model, name)
		self.dj_model = self.model
		self.model = get_user_document()

		self.dj_model.USERNAME_FIELD = self.model.USERNAME_FIELD
		username = CharField(_(name), max_length=30, unique=True)
		username = contribute_to_class(self.dj_model, self.dj_model.USERNAME_FIELD)

		self.dj_model.REQUIRED_FIELDS = self.model.REQUIRED_FIELDS
		for name in self.dj_model.REQUIRED_FIELDS:
			field = CharField(_(name), max_length=30)
			field.contribute_to_class(self.dj_model, name)

		is_staff = BoolenField(_('is_staff'), default=False)
		is_staff.contribute_to_class(self.dj_model, 'is_staff')

		is_active = BoolenField(_('is_active'), default=False)
		is_active.contribute_to_class(self.dj_model, 'is_active')

		is_superuser = BoolenField(_('is_superuser'), default=False)
		is_superuser.contribute_to_class(self.dj_model, 'is_superuser')

		last_login = DateTimeField(_('last_login'), auto_now_add=True)
		last_login.contribute_to_class(self.dj_model, 'last_login')

		date_joined = DateTimeField(_('date_joined'), autp_now_add=True)
		date_joined.contribute_to_class(self.dj_model, 'date_joined')

# 
	def get(self, *args, **kwargs):
		try:
			return self.get_queryset().get(*args, **kwargs)
		except DoesNotExist:
			raise self.dj_model.DoesNotExist


	@property
	def db(self):
		raise NoeImplementedError

	def get_quaryset(self):
		return get_user_document().objects
	
	def create_superuser(self, username, email, password, **extra_fields):
		"""
		Como nós estamos utilizando o Mongo como Banco de Dados
		Nós usamos as regras do Mongo para criar um super usuário,
		ou seja, ao invez de:
		'python manage.py createsuperuser'
		nós utilizamos: 
		'python manage.py createmongosuperuser' 
		"""

		return get_user_document().create_superuser(username, password, email)
