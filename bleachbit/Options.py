# vim: ts=4:sw=4:expandtab

# BleachBit
# Copyright (C) 2008-2025 Andrew Ziem
# https://www.bleachbit.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""
Store and retrieve user preferences
"""

# standard library imports
import errno
import logging
import os
import re

# third-party imports
if 'nt' == os.name:
    from win32file import GetLongPathName

# local application imports
import bleachbit
from bleachbit import General
from bleachbit.Language import get_text as _

logger = logging.getLogger(__name__)

boolean_keys = ['auto_hide',
                'auto_detect_lang',
                'check_beta',
                'check_online_updates',
                'dark_mode',
                'debug',
                'delete_confirmation',
                'exit_done',
                'first_start',
                'kde_shred_menu_option',
                'remember_geometry',
                'shred',
                'units_iec',
                'window_maximized',
                'window_fullscreen']
if 'nt' == os.name:
    boolean_keys.append('update_winapp2')
    boolean_keys.append('win10_theme')
int_keys = ['window_x', 'window_y', 'window_width', 'window_height', ]


def path_to_option(pathname):
    """Change a pathname to a .ini option name (a key)"""
    # On Windows change to lowercase and use backwards slashes.
    pathname = os.path.normcase(pathname)
    # On Windows expand DOS-8.3-style pathnames.
    if 'nt' == os.name and os.path.exists(pathname):
        pathname = GetLongPathName(pathname)
    if ':' == pathname[1]:
        # ConfigParser treats colons in a special way
        pathname = pathname[0] + pathname[2:]
    return pathname


def init_configuration():
    """Initialize an empty configuration, if necessary"""
    if not os.path.exists(bleachbit.options_dir):
        General.makedirs(bleachbit.options_dir)
    if os.path.lexists(bleachbit.options_file):
        logger.debug('Deleting configuration: %s ' % bleachbit.options_file)
        os.remove(bleachbit.options_file)
    with open(bleachbit.options_file, 'w', encoding='utf-8-sig') as f_ini:
        f_ini.write('[bleachbit]\n')
        if os.name == 'nt' and bleachbit.portable_mode:
            f_ini.write('[Portable]\n')
    for section in options.config.sections():
        options.config.remove_section(section)
    options.restore()


class Options:

    """Store and retrieve user preferences"""

    def __init__(self):
        self.purged = False
        self.config = bleachbit.RawConfigParser()
        self.config.optionxform = str  # make keys case sensitive for hashpath purging
        self.config.BOOLEAN_STATES['t'] = True
        self.config.BOOLEAN_STATES['f'] = False
        self.restore()

    def __flush(self):
        """Write information to disk"""
        if not self.purged:
            self.__purge()

        try:
            if not os.path.exists(bleachbit.options_dir):
                General.makedirs(bleachbit.options_dir)
            mkfile = not os.path.exists(bleachbit.options_file)
            with open(bleachbit.options_file, 'w', encoding='utf-8-sig') as _file:
                self.config.write(_file)
            if mkfile and General.sudo_mode():
                General.chownself(bleachbit.options_file)
        except (OSError, IOError, PermissionError) as e:
            if e.errno == errno.ENOSPC:
                logger.error(
                    _("Disk was full when writing configuration to file: %s"), bleachbit.options_file)
            elif e.errno == errno.EACCES:
                logger.error(
                    _("Permission denied when writing configuration to file: %s"), bleachbit.options_file)
            else:
                raise

    def __purge(self):
        """Clear out obsolete data"""
        self.purged = True
        if not self.config.has_section('hashpath'):
            return
        for option in self.config.options('hashpath'):
            pathname = option
            if 'nt' == os.name and re.search(r'^[a-z]\\', option):
                # restore colon lost because ConfigParser treats colon special
                # in keys
                pathname = pathname[0] + ':' + pathname[1:]
            exists = False
            try:
                exists = os.path.lexists(pathname)
            except:
                # this deals with corrupt keys
                # https://www.bleachbit.org/forum/bleachbit-wont-launch-error-startup
                logger.error(
                    _("Error checking whether path exists: %s"), pathname)
            if not exists:
                # the file does not on exist, so forget it
                self.config.remove_option('hashpath', option)

    def __auto_preserve_languages(self):
        """Automatically preserve the active language"""
        active_lang = bleachbit.Language.get_active_language_code()
        for lang_id in set([active_lang.split('_')[0], 'en']):
            logger.info(_("Automatically preserving language %s."), lang_id)
            self.set_language(lang_id, True)

    def __set_default(self, key, value):
        """Set the default value"""
        if not self.config.has_option('bleachbit', key):
            self.set(key, value)

    def has_option(self, option, section='bleachbit'):
        """Check if option is set"""
        return self.config.has_option(section, option)

    def get(self, option, section='bleachbit'):
        """Retrieve a general option"""
        if not 'nt' == os.name and 'update_winapp2' == option:
            return False
        if section == 'bleachit' and option == 'debug':
            from bleachbit.Log import is_debugging_enabled_via_cli
            if is_debugging_enabled_via_cli():
                # command line overrides stored configuration
                return True
        if section == 'hashpath' and option[1] == ':':
            option = option[0] + option[2:]
        if option in boolean_keys:
            return self.config.getboolean(section, option)
        elif option in int_keys:
            return self.config.getint(section, option)
        return self.config.get(section, option)

    def get_hashpath(self, pathname):
        """Recall the hash for a file"""
        return self.get(path_to_option(pathname), 'hashpath')

    def get_language(self, langid):
        """Retrieve value for whether to preserve the language"""
        if not self.config.has_section('preserve_languages'):
            self.__auto_preserve_languages()
        if not self.config.has_option('preserve_languages', langid):
            return False
        return self.config.getboolean('preserve_languages', langid)

    def get_languages(self):
        """Return a list of all selected languages"""
        if not self.config.has_section('preserve_languages'):
            self.__auto_preserve_languages()
        return self.config.options('preserve_languages')

    def get_list(self, option):
        """Return an option which is a list data type"""
        section = "list/%s" % option
        if not self.config.has_section(section):
            return None
        values = [
            self.config.get(section, option)
            for option in sorted(self.config.options(section))
        ]
        return values

    def get_paths(self, section):
        """Abstracts get_whitelist_paths and get_custom_paths"""
        if not self.config.has_section(section):
            return []
        myoptions = []
        for option in sorted(self.config.options(section)):
            pos = option.find('_')
            if -1 == pos:
                continue
            myoptions.append(option[0:pos])
        values = []
        for option in set(myoptions):
            p_type = self.config.get(section, option + '_type')
            p_path = self.config.get(section, option + '_path')
            values.append((p_type, p_path))
        return values

    def get_whitelist_paths(self):
        """Return the whitelist of paths"""
        return self.get_paths("whitelist/paths")

    def get_custom_paths(self):
        """Return list of custom paths"""
        return self.get_paths("custom/paths")

    def get_tree(self, parent, child):
        """Retrieve an option for the tree view.  The child may be None."""
        option = parent
        if child is not None:
            option += "." + child
        if not self.config.has_option('tree', option):
            return False
        try:
            return self.config.getboolean('tree', option)
        except:
            # in case of corrupt configuration (Launchpad #799130)
            logger.exception('Error in get_tree()')
            return False

    def is_corrupt(self):
        """Perform a self-check for corruption of the configuration"""
        # no boolean key must raise an exception
        for boolean_key in boolean_keys:
            try:
                if self.config.has_option('bleachbit', boolean_key):
                    self.config.getboolean('bleachbit', boolean_key)
            except ValueError:
                return True
        # no int key must raise an exception
        for int_key in int_keys:
            try:
                if self.config.has_option('bleachbit', int_key):
                    self.config.getint('bleachbit', int_key)
            except ValueError:
                return True
        return False

    def restore(self):
        """Restore saved options from disk"""
        try:
            self.config.read(bleachbit.options_file, encoding='utf-8-sig')
        except:
            logger.exception("Error reading application's configuration")
        if not self.config.has_section("bleachbit"):
            self.config.add_section("bleachbit")
        if not self.config.has_section("hashpath"):
            self.config.add_section("hashpath")
        if not self.config.has_section("list/shred_drives"):
            from bleachbit.FileUtilities import guess_overwrite_paths
            try:
                self.set_list('shred_drives', guess_overwrite_paths())
            except:
                logger.exception(
                    _("Error when setting the default drives to shred."))
        # set defaults
        self.__set_default("auto_hide", True)
        self.__set_default("auto_detect_lang", True)
        self.__set_default("check_beta", False)
        self.__set_default("check_online_updates", True)
        self.__set_default("dark_mode", True)
        self.__set_default("debug", False)
        self.__set_default("delete_confirmation", True)
        self.__set_default("exit_done", False)
        self.__set_default("kde_shred_menu_option", False)
        self.__set_default("remember_geometry", True)
        self.__set_default("shred", False)
        self.__set_default("units_iec", False)
        self.__set_default("window_fullscreen", False)
        self.__set_default("window_maximized", False)

        if 'nt' == os.name:
            self.__set_default("update_winapp2", False)
            self.__set_default("win10_theme", False)

        # BleachBit upgrade or first start ever
        if not self.config.has_option('bleachbit', 'version') or \
                self.get('version') != bleachbit.APP_VERSION:
            self.set('first_start', True)

        # set version
        self.set("version", bleachbit.APP_VERSION)

    def set(self, key, value, section='bleachbit', commit=True):
        """Set a general option"""
        self.config.set(section, key, str(value))
        if commit:
            self.__flush()

    def commit(self):
        self.__flush()

    def set_hashpath(self, pathname, hashvalue):
        """Remember the hash of a path"""
        self.set(path_to_option(pathname), hashvalue, 'hashpath')

    def set_list(self, key, values):
        """Set a value which is a list data type"""
        section = "list/%s" % key
        if self.config.has_section(section):
            self.config.remove_section(section)
        self.config.add_section(section)
        for counter, value in enumerate(values):
            self.config.set(section, str(counter), value)
        self.__flush()

    def set_whitelist_paths(self, values):
        """Save the whitelist"""
        section = "whitelist/paths"
        if self.config.has_section(section):
            self.config.remove_section(section)
        self.config.add_section(section)
        for counter, value in enumerate(values):
            self.config.set(section, str(counter) + '_type', value[0])
            self.config.set(section, str(counter) + '_path', value[1])
        self.__flush()

    def set_custom_paths(self, values):
        """Save the customlist"""
        section = "custom/paths"
        if self.config.has_section(section):
            self.config.remove_section(section)
        self.config.add_section(section)
        for counter, value in enumerate(values):
            self.config.set(section, str(counter) + '_type', value[0])
            self.config.set(section, str(counter) + '_path', value[1])
        self.__flush()

    def set_language(self, langid, value):
        """Set the value for a locale (whether to preserve it)"""
        if not self.config.has_section('preserve_languages'):
            self.config.add_section('preserve_languages')
        if self.config.has_option('preserve_languages', langid) and not value:
            self.config.remove_option('preserve_languages', langid)
        else:
            self.config.set('preserve_languages', langid, str(value))
        self.__flush()

    def set_tree(self, parent, child, value):
        """Set an option for the tree view.  The child may be None."""
        if not self.config.has_section("tree"):
            self.config.add_section("tree")
        option = parent
        if child is not None:
            option = option + "." + child
        if self.config.has_option('tree', option) and not value:
            self.config.remove_option('tree', option)
        else:
            self.config.set('tree', option, str(value))
        self.__flush()

    def toggle(self, key):
        """Toggle a boolean key"""
        self.set(key, not self.get(key))


options = Options()
