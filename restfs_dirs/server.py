#!/usr/bin/env python3

'''Directory server for RestFS'''

import sys
import json
import logging
import argparse

from flask import Flask, make_response, request

from restfs_common.constants import ADMIN, ADMIN_TOKEN, USER_TOKEN, DEFAULT_DIR_SERVICE_PORT,\
    ROOT, DIR_IDENTIFIER, DIR_CHILDS, DIR_PARENT_ID, DEFAULT_DIR_DB, HTTPS_DEBUG_MODE, URL, FILES
from restfs_common.errors import Unauthorized, ObjectNotFound, AlreadyDoneError

from restfs_client import get_AuthService

from restfs_dirs.service import DirectoryDB

# pylint: disable=too-many-statements
def routeApp(app, DIRDB, AUTH):
    '''Enruta la API REST a la webapp'''

    def _get_effective_user_(req):
        '''Get the user which send the request'''
        try:
            user = AUTH.user_of_token(req.headers.get(USER_TOKEN, None))
            return user
        except Unauthorized:
            if AUTH.is_admin(req.headers.get(ADMIN_TOKEN, None)):
                return ADMIN
        return None

    @app.route('/v1/directory/<dir_id>', methods=['GET'])
    def get_directory(dir_id):
        '''Obtiene un directorio'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            childs_names = DIRDB.get_childs_names(dir_id, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)

        childs = {}
        for child in childs_names:
            try:
                childs[child] = DIRDB.get_child_id(dir_id, child, user)
            except (ObjectNotFound, Unauthorized) as error:
                return make_response(f'Object changed during operation dispatch: {error}', 500)
        try:
            parent = DIRDB.get_parent_id(dir_id, user)
        except (ObjectNotFound, Unauthorized) as error:
            return make_response(f'Object changed during operation dispatch: {error}', 500)

        result = json.dumps({
            DIR_CHILDS: childs,
            DIR_IDENTIFIER: dir_id,
            DIR_PARENT_ID: parent
        })
        return make_response(result, 200)

    @app.route('/v1/directory/<dir_id>/<child>', methods=['PUT'])
    def make_directory(dir_id, child):
        '''Crea un subdirectorio'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            new_dir_id = DIRDB.new_directory(dir_id, child, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)

        return make_response(json.dumps({DIR_IDENTIFIER: new_dir_id}), 200)

    @app.route('/v1/directory/<dir_id>/<child>', methods=['DELETE'])
    def remove_directory(dir_id, child):
        '''Borra un subdirectorio'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            DIRDB.remove_directory(dir_id, child, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)

        return make_response('', 204)

    @app.route('/v1/files/<dir_id>', methods=['GET'])
    def get_files(dir_id):
        '''Obtiene los ficheros de un directorio'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            files = DIRDB.get_files_names(dir_id, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)

        return make_response(json.dumps({FILES: files}), 200)

    @app.route('/v1/files/<dir_id>/<filename>', methods=['GET'])
    def get_file_url(dir_id, filename):
        '''Obtiene la URL de un fichero'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            file_url = DIRDB.get_file_url(dir_id, filename, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)

        return make_response(file_url, 200)

    @app.route('/v1/files/<dir_id>/<filename>', methods=['PUT'])
    def make_file(dir_id, filename):
        '''Crea un fichero'''
        if not request.is_json:
            return make_response('Missing JSON', 400)
        request_data = request.get_json()
        if URL not in request_data:
            return make_response(f'Missing mandatory key "{URL}"', 400)

        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            DIRDB.new_file(dir_id, filename, request_data[URL], user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)

        return make_response('File created', 201)

    @app.route('/v1/files/<dir_id>/<filename>', methods=['DELETE'])
    def remove_file(dir_id, filename):
        '''Borra un fichero'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            DIRDB.remove_file(dir_id, filename, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)

        return make_response('', 204)

    @app.route('/v1/directory/<dir_id>/writable_by/<user>', methods=['PUT'])
    def add_write_permissions(dir_id, user):
        '''Otorga permisos de escritura en un directorio a un usuario'''
        owner = _get_effective_user_(request)
        if not owner:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            DIRDB.add_write_permissions_to_directory(dir_id, owner, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except AlreadyDoneError:
            return make_response('', 204)

        return make_response(f'User {user} granted with write permissions', 200)

    @app.route('/v1/directory/<dir_id>/readable_by/<user>', methods=['PUT'])
    def add_read_permissions(dir_id, user):
        '''Otorga permisos de lectura en un directorio a un usuario'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            DIRDB.add_read_permissions_to_directory(dir_id, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except AlreadyDoneError:
            return make_response('', 204)

        return make_response(f'User {user} granted with read permissions', 200)

    @app.route('/v1/directory/<dir_id>/writable_by/<user>', methods=['DELETE'])
    def remove_write_permissions(dir_id, user):
        '''Elimina permisos de escritura de un directorio a un usuario'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            DIRDB.revoke_write_permissions_to_directory(dir_id, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except AlreadyDoneError:
            return make_response('', 204)

        return make_response(f'Revoked write permissions for {user}', 200)

    @app.route('/v1/directory/<dir_id>/readable_by/<user>', methods=['DELETE'])
    def remove_read_permissions(dir_id, user):
        '''Elimina permisos de lectura de un directorio a un usuario'''
        user = _get_effective_user_(request)
        if not user:
            return make_response('Unauthorized', 401)

        if dir_id == ROOT:
            dir_id = DIRDB.root

        try:
            DIRDB.revoke_read_permissions_to_directory(dir_id, user)
        except ObjectNotFound as error:
            return make_response(f'Object not found: {error}', 404)
        except Unauthorized as error:
            return make_response(f'Unauthorized: {error}', 401)
        except AlreadyDoneError:
            return make_response('', 204)

        return make_response(f'Revoked read permissions for {user}', 200)


class DirectoryService:
    '''Wrap all components used by the service'''
    def __init__(self, db_file, auth_service,
                 host='0.0.0.0', port=DEFAULT_DIR_SERVICE_PORT):
        self._dirdb_ = DirectoryDB(db_file)
        self._auth_ = get_AuthService(auth_service)

        self._host_ = host
        self._port_ = port

        self._app_ = Flask(__name__.split('.', maxsplit=1)[0])
        routeApp(self._app_, self._dirdb_, self._auth_)

    @property
    def base_uri(self):
        '''Get the base URI to access the API'''
        host = '127.0.0.1' if self._host_ in ['0.0.0.0'] else self._host_
        return f'http://{host}:{self._port_}'

    def start(self):
        '''Start the HTTP server'''
        self._app_.run(host=self._host_, port=self._port_, debug=HTTPS_DEBUG_MODE)

    def stop(self):
        '''Do nothing'''


def main():
    '''Entry point for the auth server'''
    user_options = parse_commandline()

    service = DirectoryService(
        user_options.storage, user_options.auth_url, user_options.address, user_options.port
    )
    try:
        print(f'Starting service on: {service.base_uri}')
        service.start()
    except Exception as error: # pylint: disable=broad-except
        logging.error('Cannot start API: %s', error)
        sys.exit(1)

    service.stop()
    sys.exit(0)


def parse_commandline():
    '''Parse command line'''
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('auth_url', type=str, help='Auth service URL')
    parser.add_argument(
        '-p', '--port', type=int, default=DEFAULT_DIR_SERVICE_PORT,
        help='Listening port (default: %(default)s)', dest='port'
    )
    parser.add_argument(
        '-l', '--listening', type=str, default='0.0.0.0',
        help='Listening address (default: all interfaces)', dest='address'
    )
    parser.add_argument(
        '-s', '--storage', type=str, default=DEFAULT_DIR_DB,
        help='Database file to use (default: %(default)s)', dest='storage'
    )
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    main()
