from django.contrib.auth import backends as django_backends

class MongoEngineBackend(object):
	"""Autentica usando MongoEngine e mongoengine.django.auth.User"""

	suports_object_permissions = False
	supports_anonymous_user = False
	supports_inactive_user = False

	authenticate = django_backends.ModelBackend.__dict__['authenticate']
	get_user = django.backends.ModelBackend.__dict__['get_user']

	try:
		user_can_authenticate = django_backends.ModelBackend.__dict__['user_can_authenticate']
	except KeyError:
		pass
