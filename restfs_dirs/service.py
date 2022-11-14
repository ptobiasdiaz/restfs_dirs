#!/usr/bin/env python3

'''
    Implementacion del servicio de directorios
'''

import os
import os.path
import json
import secrets
import logging

from restfs_common.errors import Unauthorized, ObjectAlreadyExists, ObjectNotFound,\
    AlreadyDoneError
from restfs_common.constants import ADMIN, READABLE, WRITABLE, ROOT_ID, PARENT, FILES, FOLDERS,\
    DIR_IDENTIFIER_SIZE, DEFAULT_ENCODING


_WRN = logging.warning


def _initialize_(db_file):
    '''Create an empty JSON file'''
    _WRN(f'Initializing new database in file "{db_file}"')
    with open(db_file, 'w', encoding=DEFAULT_ENCODING) as contents:
        root_folder = _new_identifier_()
        json.dump({
            ROOT_ID: root_folder,
            root_folder: _new_directory_()
        }, contents)

def _new_directory_(parent=None, user=None):
    '''Return a new directory map'''
    if user is None:
        user = [ADMIN]
    elif isinstance(user, str):
        user = [user]
    else: # pragma: no cover
        raise TypeError('Unknown type for user: {user}')
    return {
        WRITABLE: user,
        READABLE: user,
        FOLDERS: {},
        FILES: {},
        PARENT: parent
    }

def _new_identifier_():
    '''Create a new token'''
    return secrets.token_urlsafe(DIR_IDENTIFIER_SIZE)


class DirectoryDB:
    '''
        Controla la base de datos persistente del servicio de directorio
    '''
    def __init__(self, db_file):
        if not os.path.exists(db_file):
            _initialize_(db_file)
        self._db_file_ = db_file

        self._directories_ = {}
        self._read_db_()

    @property
    def root(self):
        '''Return root folder ID'''
        return self._directories_[ROOT_ID]

    def _read_db_(self):
        with open(self._db_file_, 'r', encoding=DEFAULT_ENCODING) as contents:
            self._directories_ = json.load(contents)

    def _commit_(self):
        with open(self._db_file_, 'w', encoding=DEFAULT_ENCODING) as contents:
            json.dump(self._directories_, contents, indent=2, sort_keys=True)

    def _assert_dir_exists_(self, dir_id):
        '''Raises key error if dir not exists'''
        if dir_id not in self._directories_:
            raise ObjectNotFound(f'Directory #{dir_id}')

    def new_directory(self, parent, new_directory_name, user):
        '''Create a new folder in the given parent folder'''
        self._assert_dir_exists_(parent)
        if user not in self._directories_[parent][WRITABLE]:
            raise Unauthorized(user, f'Cannot write Directory #{parent}')
        if new_directory_name in self._directories_[parent][FOLDERS]:
            raise ObjectAlreadyExists(f'Directory "{new_directory_name}"')
        new_folder_id = _new_identifier_()
        self._directories_[parent][FOLDERS][new_directory_name] = new_folder_id
        self._directories_[new_folder_id] = _new_directory_(parent, user)
        self._commit_()
        return new_folder_id

    def get_childs_names(self, parent, user):
        '''Get childs of a given folder'''
        self._assert_dir_exists_(parent)
        if user not in self._directories_[parent][READABLE]:
            raise Unauthorized(user, f'Cannot read Directory #{parent}')
        return list(self._directories_[parent][FOLDERS].keys())

    def get_child_id(self, parent, child_name, user):
        '''Get childs of a given folder'''
        self._assert_dir_exists_(parent)
        if user not in self._directories_[parent][READABLE]:
            raise Unauthorized(user, f'Cannot read Directory #{parent}')
        if child_name not in self._directories_[parent][FOLDERS]:
            raise ObjectNotFound(f'Directory "{child_name}')
        return self._directories_[parent][FOLDERS][child_name]

    def get_parent_id(self, parent, user):
        '''Get childs of a given folder'''
        self._assert_dir_exists_(parent)
        if user not in self._directories_[parent][READABLE]:
            raise Unauthorized(user, f'Cannot read Directory #{parent}')
        return self._directories_[parent][PARENT]

    def remove_directory(self, parent, directory_name, user):
        '''Remove a folder from the given parent folder'''
        self._assert_dir_exists_(parent)
        if user not in self._directories_[parent][WRITABLE]:
            raise Unauthorized(user, f'Cannot write Directory #{parent}')
        if directory_name not in self._directories_[parent][FOLDERS]:
            raise ObjectNotFound(f'Directory "{directory_name}')
        directory_id = self._directories_[parent][FOLDERS][directory_name]
        del self._directories_[parent][FOLDERS][directory_name]
        del self._directories_[directory_id]
        self._commit_()

    def add_read_permissions_to_directory(self, parent, owner, user):
        '''Add read permissions to a given user'''
        self._assert_dir_exists_(parent)
        if owner not in self._directories_[parent][WRITABLE]:
            raise Unauthorized(owner, f'Cannot write Directory #{parent}')
        if user in self._directories_[parent][READABLE]:
            raise AlreadyDoneError(f'User "{user}" is in the readable ACL')
        self._directories_[parent][READABLE].append(user)
        self._commit_()

    def add_write_permissions_to_directory(self, parent, owner, user):
        '''Add write permissions to a given user'''
        self._assert_dir_exists_(parent)
        if owner not in self._directories_[parent][WRITABLE]:
            raise Unauthorized(owner, f'Cannot write Directory #{parent}')
        if user in self._directories_[parent][WRITABLE]:
            raise AlreadyDoneError(f'User "{user}" is in the writable ACL')
        self._directories_[parent][WRITABLE].append(user)
        self._commit_()

    def revoke_read_permissions_to_directory(self, parent, owner, user):
        '''Revoke read permissions to a given user'''
        self._assert_dir_exists_(parent)
        if owner not in self._directories_[parent][WRITABLE]:
            raise Unauthorized(owner, f'Cannot write Directory #{parent}')
        if user not in self._directories_[parent][READABLE]:
            raise AlreadyDoneError(f'User "{user}" in not in the readable ACL')
        self._directories_[parent][READABLE].remove(user)
        self._commit_()

    def revoke_write_permissions_to_directory(self, parent, owner, user):
        '''Revoke write permissions to a given user'''
        self._assert_dir_exists_(parent)
        if owner not in self._directories_[parent][WRITABLE]:
            raise Unauthorized(owner, f'Cannot write Directory #{parent}')
        if user not in self._directories_[parent][WRITABLE]:
            raise AlreadyDoneError(f'User "{user}" is not in then writable ACL')
        self._directories_[parent][WRITABLE].remove(user)
        self._commit_()

    def check_read_permissions_to_directory(self, parent, user):
        '''Check read permissions to a given user'''
        self._assert_dir_exists_(parent)
        return user in self._directories_[parent][READABLE]

    def check_write_permissions_to_directory(self, parent, user):
        '''Add write permissions to a given user'''
        self._assert_dir_exists_(parent)
        return user in self._directories_[parent][WRITABLE]

    def new_file(self, parent, new_filename, file_url, user):
        '''Create a new file in the given parent folder'''
        self._assert_dir_exists_(parent)
        if user not in self._directories_[parent][WRITABLE]:
            raise Unauthorized(user, f'Cannot write Directory #{parent}')
        if new_filename in self._directories_[parent][FILES]:
            raise ObjectAlreadyExists(f'File "{new_filename}" on Directory #{parent}')
        self._directories_[parent][FILES][new_filename] = file_url
        self._commit_()

    def remove_file(self, parent, filename, user):
        '''Remove a file from the given parent folder'''
        self._assert_dir_exists_(parent)
        if user not in self._directories_[parent][WRITABLE]:
            raise Unauthorized(user, f'Cannot write Directory #{parent}')
        if filename not in self._directories_[parent][FILES]:
            raise ObjectNotFound(f'File "{filename}" on Directory #{parent}')
        del self._directories_[parent][FILES][filename]
        self._commit_()

    def get_files_names(self, parent, user):
        '''Get files of a given folder'''
        self._assert_dir_exists_(parent)
        if user not in self._directories_[parent][READABLE]:
            raise Unauthorized(user, f'Cannot read Directory #{parent}')
        return list(self._directories_[parent][FILES].keys())

    def get_file_url(self, parent, filename, user):
        '''Get file URL of a given filename'''
        self._assert_dir_exists_(parent)
        if user not in self._directories_[parent][READABLE]:
            raise Unauthorized(user, f'Cannot read Directory #{parent}')
        if filename not in self._directories_[parent][FILES]:
            raise ObjectNotFound(f'File "{filename}" on Directory #{parent}')
        return self._directories_[parent][FILES][filename]
