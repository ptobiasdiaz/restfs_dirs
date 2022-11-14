#!/usr/bin/env python3

import os
import os.path
import tempfile
import unittest

from restfs_common.constants import ADMIN
from restfs_common.errors import ObjectAlreadyExists, ObjectNotFound, Unauthorized,\
    AlreadyDoneError

from restfs_dirs.service import DirectoryDB


USER1 = 'test_user1'
USER2 = 'test_user2'

DIR1 = 'test_directory1'
DIR2 = 'test_directory2'

FILE1 = 'test_filename1'
FILE2 = 'test_filename2'

FILE_URL = 'some_file_url'
WRONG_DIRECTORY_ID = 'wrong_directory_id'


class TestDirectoryDB(unittest.TestCase):

    def test_creation(self):
        '''Test initialization'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)
            self.assertTrue(os.path.exists(dbfile))
            self.assertTrue(dirdb.check_read_permissions_to_directory(dirdb.root, ADMIN))
            self.assertTrue(dirdb.check_write_permissions_to_directory(dirdb.root, ADMIN))
            self.assertListEqual(dirdb.get_childs_names(dirdb.root, ADMIN), [])
            self.assertListEqual(dirdb.get_files_names(dirdb.root, ADMIN), [])
            self.assertIsNone(dirdb.get_parent_id(dirdb.root, ADMIN))

    def test_create_new_folder(self):
        '''Test create new folder'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            new_dir = dirdb.new_directory(dirdb.root, DIR1, ADMIN)
            self.assertTrue(dirdb.check_read_permissions_to_directory(new_dir, ADMIN))
            self.assertTrue(dirdb.check_write_permissions_to_directory(new_dir, ADMIN))
            self.assertIn(DIR1, dirdb.get_childs_names(dirdb.root, ADMIN))
            self.assertEqual(new_dir, dirdb.get_child_id(dirdb.root, DIR1, ADMIN))
            self.assertEqual(dirdb.get_parent_id(new_dir, ADMIN), dirdb.root)

    def test_create_new_folder_wrong_parent(self):
        '''Test create folder with wrong parent'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(ObjectNotFound):
                new_dir = dirdb.new_directory(WRONG_DIRECTORY_ID, DIR1, ADMIN)

    def test_create_new_folder_wrong_user(self):
        '''Test create folder with wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(Unauthorized):
                new_dir = dirdb.new_directory(dirdb.root, DIR1, USER1)

    def test_create_duplicated_folder(self):
        '''Test create duplicated folder'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            new_dir = dirdb.new_directory(dirdb.root, DIR1, ADMIN)
            with self.assertRaises(ObjectAlreadyExists):
                new_dir = dirdb.new_directory(dirdb.root, DIR1, ADMIN)

    def test_remove_folder(self):
        '''Test remove folder'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            new_dir = dirdb.new_directory(dirdb.root, DIR1, ADMIN)

            dirdb.remove_directory(dirdb.root, DIR1, ADMIN)
            self.assertListEqual(dirdb.get_childs_names(dirdb.root, ADMIN), [])

    def test_remove_folder_wrong_folder(self):
        '''Test remove folder'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(ObjectNotFound):
                dirdb.remove_directory(dirdb.root, DIR1, ADMIN)

    def test_remove_folder_wrong_user(self):
        '''Test remove folder with wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            new_dir = dirdb.new_directory(dirdb.root, DIR1, ADMIN)
            with self.assertRaises(Unauthorized):
                dirdb.remove_directory(dirdb.root, DIR1, USER1)

    def test_query_wrong_subdirectory(self):
        '''Test query for a non exists child'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(ObjectNotFound):
                dirdb.get_child_id(dirdb.root, DIR1, ADMIN)

    def test_query_childs_wrong_user(self):
        '''Test query for a non exists child'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(Unauthorized):
                dirdb.get_childs_names(dirdb.root, USER1)

    def test_query_parent_wrong_user(self):
        '''Test query for a non exists child'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(Unauthorized):
                dirdb.get_parent_id(dirdb.root, USER1)

    def test_query_ids_with_wrong_user(self):
        '''Test query child ids with a wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)
            new_dir = dirdb.new_directory(dirdb.root, DIR1, ADMIN)

            with self.assertRaises(Unauthorized):
                dirdb.get_child_id(dirdb.root, DIR1, USER1)

    def test_grant_read_access_to_folder(self):
        '''Test grant access to a folder'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            self.assertFalse(dirdb.check_read_permissions_to_directory(dirdb.root, USER1))
            dirdb.add_read_permissions_to_directory(dirdb.root, ADMIN, USER1)
            self.assertTrue(dirdb.check_read_permissions_to_directory(dirdb.root, USER1))

    def test_grant_write_access_to_folder(self):
        '''Test grant access to a folder'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            self.assertFalse(dirdb.check_write_permissions_to_directory(dirdb.root, USER1))
            dirdb.add_write_permissions_to_directory(dirdb.root, ADMIN, USER1)
            self.assertTrue(dirdb.check_write_permissions_to_directory(dirdb.root, USER1))

    def test_grant_read_access_to_folder_wrong_owner(self):
        '''Test grant access to a folder with wrong owner'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(Unauthorized):
                dirdb.add_read_permissions_to_directory(dirdb.root, USER1, USER2)

    def test_grant_write_access_to_folder_wrong_owner(self):
        '''Test grant access to a folder with wrong owner'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(Unauthorized):
                dirdb.add_write_permissions_to_directory(dirdb.root, USER1, USER2)

    def test_grant_read_access_to_folder_already_granted(self):
        '''Test grant access to a folder with wrong owner'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            dirdb.add_read_permissions_to_directory(dirdb.root, ADMIN, USER1)
            with self.assertRaises(AlreadyDoneError):
                dirdb.add_read_permissions_to_directory(dirdb.root, ADMIN, USER1)

    def test_grant_write_access_to_folder_already_granted(self):
        '''Test grant access to a folder with wrong owner'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            dirdb.add_write_permissions_to_directory(dirdb.root, ADMIN, USER1)
            with self.assertRaises(AlreadyDoneError):
                dirdb.add_write_permissions_to_directory(dirdb.root, ADMIN, USER1)

    def test_revoke_read_access_to_folder(self):
        '''Test revoke access to a folder'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            dirdb.add_read_permissions_to_directory(dirdb.root, ADMIN, USER1)
            self.assertTrue(dirdb.check_read_permissions_to_directory(dirdb.root, USER1))
            dirdb.revoke_read_permissions_to_directory(dirdb.root, ADMIN, USER1)
            self.assertFalse(dirdb.check_read_permissions_to_directory(dirdb.root, USER1))

    def test_revoke_write_access_to_folder(self):
        '''Test revoke access to a folder'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            dirdb.add_write_permissions_to_directory(dirdb.root, ADMIN, USER1)
            self.assertTrue(dirdb.check_write_permissions_to_directory(dirdb.root, USER1))
            dirdb.revoke_write_permissions_to_directory(dirdb.root, ADMIN, USER1)
            self.assertFalse(dirdb.check_write_permissions_to_directory(dirdb.root, USER1))

    def test_revoke_read_access_to_folder_wrong_owner(self):
        '''Test revoke access to a folder with wrong owner'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(Unauthorized):
                dirdb.revoke_read_permissions_to_directory(dirdb.root, USER1, USER2)

    def test_revoke_write_access_to_folder_wrong_owner(self):
        '''Test revoke access to a folder with wrong owner'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(Unauthorized):
                dirdb.revoke_write_permissions_to_directory(dirdb.root, USER1, USER2)

    def test_revoke_read_access_to_folder_user_not_granted(self):
        '''Test revoke access to a folder of an user not granted'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(AlreadyDoneError):
                dirdb.revoke_read_permissions_to_directory(dirdb.root, ADMIN, USER1)

    def test_revoke_write_access_to_folder_user_not_granted(self):
        '''Test revoke access to a folder of an user not granted'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(AlreadyDoneError):
                dirdb.revoke_write_permissions_to_directory(dirdb.root, ADMIN, USER1)

    def test_new_file(self):
        '''Test create new file'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            dirdb.new_file(dirdb.root, FILE1, FILE_URL, ADMIN)
            self.assertIn(FILE1, dirdb.get_files_names(dirdb.root, ADMIN))
            self.assertEqual(FILE_URL, dirdb.get_file_url(dirdb.root, FILE1, ADMIN))

    def test_new_file_wrong_user(self):
        '''Test create new file with wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(Unauthorized):
                dirdb.new_file(dirdb.root, FILE1, FILE_URL, USER1)

    def test_new_file_but_duplicated(self):
        '''Test create a duplicated file'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            dirdb.new_file(dirdb.root, FILE1, FILE_URL, ADMIN)
            with self.assertRaises(ObjectAlreadyExists):
                dirdb.new_file(dirdb.root, FILE1, FILE_URL, ADMIN)

    def test_remove_file(self):
        '''Test remove a file'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            dirdb.new_file(dirdb.root, FILE1, FILE_URL, ADMIN)
            dirdb.remove_file(dirdb.root, FILE1, ADMIN)
            self.assertNotIn(FILE1, dirdb.get_files_names(dirdb.root, ADMIN))

    def test_remove_file_wrong_user(self):
        '''Test remove a file with wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            dirdb.new_file(dirdb.root, FILE1, FILE_URL, ADMIN)
            with self.assertRaises(Unauthorized):
                dirdb.remove_file(dirdb.root, FILE1, USER1)

    def test_remove_file_not_exists(self):
        '''Test remove a file that not exists'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(ObjectNotFound):
                dirdb.remove_file(dirdb.root, FILE1, ADMIN)

    def test_get_filenames_wrong_user(self):
        '''Test get filenames with a wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(Unauthorized):
                dirdb.get_files_names(dirdb.root, USER1)

    def test_get_file_url_wrong_user(self):
        '''Test get file URL with a wrong user'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            dirdb.new_file(dirdb.root, FILE1, FILE_URL, ADMIN)
            with self.assertRaises(Unauthorized):
                dirdb.get_file_url(dirdb.root, FILE1, USER1)

    def test_get_file_url_wrong_file(self):
        '''Test get file URL with a wrong filename'''
        with tempfile.TemporaryDirectory() as workspace:
            dbfile = os.path.join(workspace, 'dirdb.json')
            dirdb = DirectoryDB(dbfile)

            with self.assertRaises(ObjectNotFound):
                dirdb.get_file_url(dirdb.root, FILE1, ADMIN)
