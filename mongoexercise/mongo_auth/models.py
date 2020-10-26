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
	app_label = fields.StringField(max_length=100)
	model = fields.StringField(max_length=100, verbose_name=_('python model class name'),
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

	name = fields.StringField(max_length=50, verbose_name=_('username'))
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

	username = fields.StringField(
		max_length=150, verbose_name=_('use name')
		help_text=("Required. 150 characters or fewer. Letters, numbers and @/./+/-/_ characters")
	)

	first_name = fields.StringField(
		max_length=30, blank=True, verbose_name=_('first name')
	)

	last_name = fields.StringField(
		max_length=30, blank=True, verbose_name=_('last name')
	)

	email = fields.EmailEmailField(verbose_name=_('email address'), blank=True)

	password = fields.StringField(
		max_length=30, blank=True, verbose_name=_('password'),
		help_text=_("Use '[algo]$[iterations]$[salt]$[hexdigest]' or use the <a href=\"password/\">change password form</a>.")
	)

	is_staff = fields.BooleanField(
		default=False,
		verbose_name=_('staff status'),
		help_text=_("Designado para que o usuário possa logar no site admin")
	)

	is_active = fields.BooleanField(
		default=True,
		verbose_name=_('active'),
		help_text=_("Designado para ver se o usuário deveria ser tratado como ativo")
	)

	is_superuser = fields.BooleanField(
		default=False,
		verbose_name=_('super user'),
		help_text=_("Se o usuário possui todas as permissões")
	)	

	last_login = fields.DateTimeField(
		verbose_name=_('last login'),
		default=timezone.now
	)

	date_joined = fields.DateTimeField(
		default=timezone.now,
		verbose_name=_('date joined')
	)

	user_permissions = fields.ListField(
		fields.ReferenceField(Permission),
		verbose_name=_('user permission'),
		blank=True,
		help_text=_("Permissões para o usuário")
	)

	USERNAME_FIELD = getattr(settings, 'MONGOENGINE_USERNAME_FIELDS', 'username')
	REQUIRED_FIELDS = getattr(settings, 'MONGOENGINE_USER_REQUIRED_FIELDS', ['email'])

	meta = {
		'abstract': True,
		'indexes':[
			{'fields': ['username'], 'unique': True, 'sparse':True}
		]
	}

	def __unicode__(self):
		return self.username

	def get_full_name(self):
        """Returns the users first and last names, separated by a space.
        """
        full_name = u'%s %s' % (self.first_name or '', self.last_name or '')
        return full_name.strip()

    def set_password(self, raw_password):
        """Sets the user's password - always use this rather than directly
        assigning to :attr:`~mongoengine.django.auth.User.password` as the
        password is hashed before storage.
        """
        self.password = make_password(raw_password)
        self.save()
        return self

    def check_password(self, raw_password):
        """Checks the user's password against a provided password - always use
        this rather than directly comparing to
        :attr:`~mongoengine.django.auth.User.password` as the password is
        hashed before storage.
        """
        return check_password(raw_password, self.password)

    @classmethod
    def _create_user(cls, username, password, email=None, create_superuser=False):
        """Create (and save) a new user with the given username, password and
                email address.
                """
        now = timezone.now()

        # Normalize the address by lowercasing the domain part of the email
        # address.
        if email is not None:
            try:
                email_name, domain_part = email.strip().split('@', 1)
            except ValueError:
                pass
            else:
                email = '@'.join([email_name, domain_part.lower()])

        user = cls(username=username, email=email, date_joined=now)
        user.set_password(password)
        if create_superuser:
            user.is_staff = True
            user.is_superuser = True
        user.save()
        return user

    @classmethod
    def create_user(cls, username, password, email=None):
        return cls._create_user(username, password, email)

    @classmethod
    def create_superuser(cls, username, password, email=None):
        return cls._create_user(username, password, email, create_superuser=True)

    def get_group_permissions(self, obj=None):
        """
        Returns a list of permission strings that this user has through his/her
        groups. This method queries all available auth backends. If an object
        is passed in, only permissions matching this object are returned.
        """
        permissions = set()
        for backend in auth.get_backends():
            if hasattr(backend, "get_group_permissions"):
                permissions.update(backend.get_group_permissions(self, obj))
        return permissions

    def get_all_permissions(self, obj=None):
        return _user_get_permissions(self, obj, 'all')

    def has_perm(self, perm, obj=None):
        """
        Returns True if the user has the specified permission. This method
        queries all available auth backends, but returns immediately if any
        backend returns True. Thus, a user who has permission from a single
        auth backend is assumed to have permission in general. If an object is
        provided, permissions for this specific object are checked.
        """

        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        # Otherwise we need to check the backends.
        return _user_has_perm(self, perm, obj)
    
    def has_perms(self, perm_list, obj=None):
        """
        Returns True if the user has each of the specified permissions. If
        object is passed, it checks if the user has all required perms for this
        object.
        """
        for perm in perm_list:
            if not self.has_perm(perm, obj):
                return False
        return True

    def has_module_perms(self, app_label):
        """
        Returns True if the user has any permissions in the given app label.
        Uses pretty much the same logic as has_perm, above.
        """
        # Active superusers have all permissions.
        if self.is_active and self.is_superuser:
            return True

        return _user_has_module_perms(self, app_label)

    def email_user(self, subject, message, from_email=None):
        "Sends an e-mail to this User."
        from django.core.mail import send_mail
        send_mail(subject, message, from_email, [self.email])

    def get_profile(self):
        """
        Returns site-specific profile for this user. Raises
        SiteProfileNotAvailable if this site does not allow profiles.
        """
        if not hasattr(self, '_profile_cache'):
            if not getattr(settings, 'AUTH_PROFILE_MODULE', False):
                raise SiteProfileNotAvailable('You need to set AUTH_PROFILE_MO'
                                              'DULE in your project settings')
            try:
                app_label, model_name = settings.AUTH_PROFILE_MODULE.split('.')
            except ValueError:
                raise SiteProfileNotAvailable('app_label and model_name should'
                        ' be separated by a dot in the AUTH_PROFILE_MODULE set'
                        'ting')

            try:
                model = models.get_model(app_label, model_name)
                if model is None:
                    raise SiteProfileNotAvailable('Unable to load the profile '
                        'model, check AUTH_PROFILE_MODULE in your project sett'
                        'ings')
                self._profile_cache = model._default_manager.using(self._state.db).get(user__id__exact=self.id)
                self._profile_cache.user = self
            except (ImportError, ImproperlyConfigured):
                raise SiteProfileNotAvailable
        return self._profile_cache


class User(AbstractUser):
	meta = {'allow_inheritance':True}


class MongoUser(BaseUser, models.Model):
	"""
	MongoUser é usado para substituir o UserManager com MongoUserManager.

	Para conseguir a classe document do usuário usar get_user_document().
	"""

	objects = MongoUserManager()

	class Meta:
		app_label = 'mongo_auth'

	def set_password(self, password):
		"""Não faz nada, mas trabalha em torno com Djangp 1.6"""
		make_password(password)


MongoUser._meta.pk.tp_python = ObjectId