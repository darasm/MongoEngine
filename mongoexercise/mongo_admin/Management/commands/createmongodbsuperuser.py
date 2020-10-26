"""Utilitario de Gerenciamento para criar superusers"""

#entrada de senha portatil
import getpass

#Expressões regulares
import re
import sys

#Uma biblioteca para parse das opções da linha de comando
from optparse import make_option

from django_mongoengine.mongo_auth.model import MongoUser
from django_mongoengine.session import DEFAULT_CONNECTION_NAME
from djangp.core import exceptions
from django.core.management.base import BaseCommand, CommandError
from djangp.utils.translation import ugettext as _ 

get_default_username = lambda: "admin"

RE_VALID_USERNAME = re.compile('[\w.@+-]+$')

EMAIL_RE = re.compile(
    r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"  # dot-atom
    r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"' # quoted-string
    r')@(?:[A-Z0-9-]+\.)+[A-Z]{2,6}$', re.IGNORECASE)  # domain

def is_valid_email(value):
	if not EMAIL_RE.search(value):
		raise exceptions.ValidationError(_('Digite um endereço de email válido'))


class Command(BaseCommand):
	help = 'Usado para criar o superuser'

	def add_argument(self, parser):
		parser.add_argument(
			'--username', dest='username', default=None,
			help='Especifica o nome do usuario para o superusuario'
		)

		parser.add_argument(
			'--email', dest='email', default=None,
			help='Especifica o endereço de email para o superusuario'
		)

		parser.add_argument(
			'--noinput', action='store_false', dest='interactive', default=True,
			help=('Diz ao django para nao solicitar ao usuário qualquer tipo de entrada')
		)

		parser.add_argument(
			'--database', action='store', dest='database',
			default=DEFAULT_CONNECTION_NAME, help='Especifica o banco de dados a ser usado'
		)


	def handle(self, *args, **options):
		username = options.get('username', None)
        email = options.get('email', None)
        interactive = options.get('interactive')
        verbosity = int(options.get('verbosity', 1))
        database = options.get('database')

        # Do quick and dirty validation if --noinput
        if not interactive:
            if not username or not email:
                raise CommandError("You must use --username and --email with --noinput.")
            if not RE_VALID_USERNAME.match(username):
                raise CommandError("Invalid username. Use only letters, digits, and underscores")
            try:
                is_valid_email(email)
            except exceptions.ValidationError:
                raise CommandError("Invalid email address.")

        # If not provided, create the user with an unusable password
        password = None

        # Prompt for username/email/password. Enclose this whole thing in a
        # try/except to trap for a keyboard interrupt and exit gracefully.
        if interactive:
            default_username = get_default_username()
            try:

                # Pega  o nome do usuario
                while 1:
                    if not username:
                        input_msg = 'Username'
                        if default_username:
                            input_msg += ' (leave blank to use %r)' % default_username
                        if sys.version_info < (3,):
                            username = raw_input(input_msg + ': ')
                        else:
                            username = input(input_msg + ': ')
                    if default_username and username == '':
                        username = default_username
                    if not RE_VALID_USERNAME.match(username):
                        sys.stderr.write("Error: That username is invalid. Use only letters, digits and underscores.\n")
                        username = None
                        continue
                    try:
                        MongoUser.objects.get(username=username)
                    except MongoUser.DoesNotExist:
                        break
                    else:
                        sys.stderr.write("Error: That username is already taken.\n")
                        username = None

                # Pega o email
                while 1:
                    if not email:
                        if sys.version_info < (3,):
                            email = raw_input('E-mail address: ')
                        else:
                            email = input('E-mail address: ')
                    try:
                        is_valid_email(email)
                    except exceptions.ValidationError:
                        sys.stderr.write("Error: That e-mail address is invalid.\n")
                        email = None
                    else:
                        break

                # Pega a senha
                while 1:
                    if not password:
                        password = getpass.getpass()
                        password2 = getpass.getpass('Password (again): ')
                        if password != password2:
                            sys.stderr.write("Error: Your passwords didn't match.\n")
                            password = None
                            continue
                    if password.strip() == '':
                        sys.stderr.write("Error: Blank passwords aren't allowed.\n")
                        password = None
                        continue
                    break
            except KeyboardInterrupt:
                sys.stderr.write("\nOperation cancelled.\n")
                sys.exit(1)

        MongoUser.objects.create_superuser(username, email, password)
        if verbosity >= 1:
          self.stdout.write("Superuser created successfully.\n")
