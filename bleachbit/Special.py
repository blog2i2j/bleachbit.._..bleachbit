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
Cross-platform, special cleaning operations
"""

# standard library imports
import contextlib
import json
import logging
import os.path
import sqlite3
import xml.dom.minidom
from urllib.parse import urlparse, urlunparse


# local application imports
from bleachbit import FileUtilities
from bleachbit.Options import options

logger = logging.getLogger(__name__)


def __get_chrome_history(path, fn='History'):
    """Get Google Chrome or Chromium history version.

    'path' is name of any file in same directory"""
    path_history = os.path.join(os.path.dirname(path), fn)
    ver = get_sqlite_int(
        path_history, 'select value from meta where key="version"')[0]
    assert ver > 1
    return ver


def _sqlite_table_exists(pathname, table):
    """Check whether a table exists in the SQLite database"""
    cmd = "select name from sqlite_master where type='table' and name=?;"
    with contextlib.closing(sqlite3.connect(pathname)) as conn:
        if conn.execute(cmd, (table,)).fetchone():
            return True
    return False


def __shred_sqlite_char_columns(table, cols=None, where="", path=None):
    """Create an SQL command to shred character columns"""
    if path and not _sqlite_table_exists(path, table):
        return ""
    cmd = ""
    if not where:
        # If None, set to empty string.
        where = ""
    if cols and options.get('shred'):
        for blob_type in ('randomblob', 'zeroblob'):
            updates = [f'{col} = {blob_type}(length({col}))' for col in cols]
            cmd += f"update or ignore {table} set {', '.join(updates)} {where};"
    cmd += f"delete from {table} {where};"
    return cmd


def get_sqlite_int(path, sql, parameters=()):
    """Run SQL on database in 'path' and return the integers"""
    def row_factory(_cursor, row):
        """Convert row to integer"""
        return int(row[0])
    return _get_sqlite_values(path, sql, row_factory, parameters)


def _get_sqlite_values(path, sql, row_factory=None, parameters=()):
    """Run SQL on database in 'path' and return the integers"""
    with contextlib.closing(sqlite3.connect(path)) as conn:
        if row_factory is not None:
            conn.row_factory = row_factory
        cursor = conn.execute(sql, parameters)
        return cursor.fetchall()


def delete_chrome_autofill(path):
    """Delete autofill table in Chromium/Google Chrome 'Web Data' database"""
    cols = ('name', 'value', 'value_lower')
    cmds = __shred_sqlite_char_columns('autofill', cols, path=path)

    # autofill_profile_* existed for years until Google Chrome stable released August 2023
    cols = ('first_name', 'middle_name', 'last_name', 'full_name')
    cmds += __shred_sqlite_char_columns(
        'autofill_profile_names', cols, path=path)
    cmds += __shred_sqlite_char_columns('autofill_profile_emails',
                                        ('email',), path=path)
    cmds += __shred_sqlite_char_columns('autofill_profile_phones',
                                        ('number',), path=path)
    cols = ('company_name', 'street_address', 'dependent_locality',
            'city', 'state', 'zipcode', 'country_code')
    cmds += __shred_sqlite_char_columns('autofill_profiles', cols, path=path)

    # local_addresses* appeared in Google Chrome stable versions released August 2023
    cols = ('guid', 'use_count', 'use_date', 'date_modified',
            'language_code', 'label', 'initial_creator_id', 'last_modifier_id')
    cmds += __shred_sqlite_char_columns('local_addresses', cols, path=path)

    cols = ('guid', 'type', 'value', 'verification_status')
    cmds += __shred_sqlite_char_columns(
        'local_addresses_type_tokens', cols, path=path)

    cols = (
        'company_name', 'street_address', 'address_1', 'address_2', 'address_3', 'address_4',
        'postal_code', 'country_code', 'language_code', 'recipient_name', 'phone_number')
    cmds += __shred_sqlite_char_columns('server_addresses', cols, path=path)
    FileUtilities.execute_sqlite3(path, cmds)


def delete_chrome_databases_db(path):
    """Delete remote HTML5 cookies (avoiding extension data) from the Databases.db file"""
    cols = ('origin', 'name', 'description')
    where = "where origin not like 'chrome-%'"
    cmds = __shred_sqlite_char_columns('Databases', cols, where, path)
    FileUtilities.execute_sqlite3(path, cmds)


def delete_chrome_favicons(path):
    """Delete Google Chrome and Chromium favicons not use in in history for bookmarks"""

    path_history = os.path.join(os.path.dirname(path), 'History')
    if os.path.exists(path_history):
        ver = __get_chrome_history(path)
    else:
        # assume it's the newer version
        ver = 38
    cmds = ""

    if ver >= 4:
        # Version 4 includes Chromium 12
        # Version 20 includes Chromium 14, Google Chrome 15, Google Chrome 19
        # Version 22 includes Google Chrome 20
        # Version 25 is Google Chrome 26
        # Version 26 is Google Chrome 29
        # Version 28 is Google Chrome 30
        # Version 29 is Google Chrome 37
        # Version 32 is Google Chrome 51
        # Version 36 is Google Chrome 60
        # Version 38 is Google Chrome 64
        # Version 42 is Google Chrome 79

        # icon_mapping
        cols = ('page_url',)
        where = None
        if os.path.exists(path_history):
            cmds += f"attach database \"{path_history}\" as History;"
            where = "where page_url not in (select distinct url from History.urls)"
        cmds += __shred_sqlite_char_columns('icon_mapping', cols, where, path)

        # favicon images
        cols = ('image_data', )
        where = "where icon_id not in (select distinct icon_id from icon_mapping)"
        cmds += __shred_sqlite_char_columns('favicon_bitmaps',
                                            cols, where, path)

        # favicons
        # Google Chrome 30 (database version 28): image_data moved to table
        # favicon_bitmaps
        if ver < 28:
            cols = ('url', 'image_data')
        else:
            cols = ('url', )
        where = "where id not in (select distinct icon_id from icon_mapping)"
        cmds += __shred_sqlite_char_columns('favicons', cols, where, path)
    elif 3 == ver:
        # Version 3 includes Google Chrome 11

        cols = ('url', 'image_data')
        where = None
        if os.path.exists(path_history):
            cmds += f"attach database \"{path_history}\" as History;"
            where = "where id not in(select distinct favicon_id from History.urls)"
        cmds += __shred_sqlite_char_columns('favicons', cols, where, path)
    else:
        raise RuntimeError(f'{path} is version {ver}')

    FileUtilities.execute_sqlite3(path, cmds)


def delete_chrome_history(path):
    """Clean history from History and Favicon files without affecting bookmarks"""
    if not os.path.exists(path):
        logger.debug(
            'aborting delete_chrome_history() because history does not exist: %s', path)
        return
    cols = ('url', 'title')
    where = ""
    ids_int = get_chrome_bookmark_ids(path)
    if ids_int:
        ids_str = ",".join([str(id0) for id0 in ids_int])
        where = f"where id not in ({ids_str})"
    cmds = __shred_sqlite_char_columns('urls', cols, where, path)
    cmds += __shred_sqlite_char_columns('visits', path=path)
    # Google Chrome 79 no longer has lower_term in keyword_search_terms
    cols = ('term',)
    cmds += __shred_sqlite_char_columns('keyword_search_terms',
                                        cols, path=path)
    ver = __get_chrome_history(path)
    if ver >= 20:
        # downloads, segments, segment_usage first seen in Chrome 14,
        #   Google Chrome 15 (database version = 20).
        # Google Chrome 30 (database version 28) doesn't have full_path, but it
        # does have current_path and target_path
        if ver >= 28:
            cmds += __shred_sqlite_char_columns(
                'downloads', ('current_path', 'target_path'), path=path)
            cmds += __shred_sqlite_char_columns(
                'downloads_url_chains', ('url', ), path=path)
        else:
            cmds += __shred_sqlite_char_columns(
                'downloads', ('full_path', 'url'), path=path)
        cmds += __shred_sqlite_char_columns('segments', ('name',), path=path)
        cmds += __shred_sqlite_char_columns('segment_usage', path=path)
    FileUtilities.execute_sqlite3(path, cmds)


def delete_chrome_keywords(path):
    """Delete keywords table in Chromium/Google Chrome 'Web Data' database"""
    cols = ('short_name', 'keyword', 'favicon_url',
            'originating_url', 'suggest_url')
    where = "where not date_created = 0"
    cmds = __shred_sqlite_char_columns('keywords', cols, where, path)
    cmds += "update keywords set usage_count = 0;"
    ver = __get_chrome_history(path, 'Web Data')
    if 43 <= ver < 49:
        # keywords_backup table first seen in Google Chrome 17 / Chromium 17
        # which is Web Data version 43.
        # In Google Chrome 25, the table is gone.
        cmds += __shred_sqlite_char_columns('keywords_backup',
                                            cols, where, path)
        cmds += "update keywords_backup set usage_count = 0;"

    FileUtilities.execute_sqlite3(path, cmds)


def delete_office_registrymodifications(path):
    """Erase LibreOffice 3.4 and Apache OpenOffice.org 3.4 MRU in registrymodifications.xcu"""
    dom1 = xml.dom.minidom.parse(path)
    modified = False
    pathprefix = '/org.openoffice.Office.Histories/Histories/'
    for node in dom1.getElementsByTagName("item"):
        if not node.hasAttribute("oor:path"):
            continue
        if not node.getAttribute("oor:path").startswith(pathprefix):
            continue
        node.parentNode.removeChild(node)
        node.unlink()
        modified = True
    if modified:
        with open(path, 'w', encoding='utf-8') as xml_file:
            dom1.writexml(xml_file)


def delete_mozilla_url_history(path):
    """Delete URL history in Mozilla places.sqlite (Firefox 3 and family)"""

    cmds = ""

    have_places = _sqlite_table_exists(path, 'moz_places')

    if have_places:
        # delete the URLs in moz_places
        places_suffix = "where id in (select " \
            "moz_places.id from moz_places " \
            "left join moz_bookmarks on moz_bookmarks.fk = moz_places.id " \
            "where moz_bookmarks.id is null); "

        cols = ('url', 'rev_host', 'title')
        cmds += __shred_sqlite_char_columns('moz_places',
                                            cols, places_suffix, path)

        # For any bookmarks that remain in moz_places, reset the non-character values.
        cmds += "update moz_places set visit_count=0, frecency=-1, last_visit_date=null;"

        # delete any orphaned annotations in moz_annos
        annos_suffix = "where id in (select moz_annos.id " \
            "from moz_annos " \
            "left join moz_places " \
            "on moz_annos.place_id = moz_places.id " \
            "where moz_places.id is null); "

        cmds += __shred_sqlite_char_columns(
            'moz_annos', ('content', ), annos_suffix, path)

    # Delete any orphaned favicons.
    # Firefox 78 no longer has a table named moz_favicons, and it no
    # longer has a column favicon_id in the table moz_places. This
    # change probably happened before version 78.
    if have_places and _sqlite_table_exists(path, 'moz_favicons'):
        fav_suffix = "where id not in (select favicon_id " \
            "from moz_places where favicon_id is not null ); "
        cols = ('url', 'data')
        cmds += __shred_sqlite_char_columns('moz_favicons',
                                            cols, fav_suffix, path)

    # Delete orphaned origins.
    if have_places and _sqlite_table_exists(path, 'moz_origins'):
        origins_where = 'where id not in (select distinct origin_id from moz_places)'
        cmds += __shred_sqlite_char_columns('moz_origins',
                                            ('host',), origins_where, path)
        # For any remaining origins, reset the statistic.
        cmds += "update moz_origins set frecency=-1;"

    if _sqlite_table_exists(path, 'moz_meta'):
        cmds += "delete from moz_meta where key like 'origin_frecency_%';"

    # Delete all history visits.
    cmds += "delete from moz_historyvisits;"

    # delete any orphaned input history
    if have_places:
        input_suffix = "where place_id not in (select distinct id from moz_places)"
        cols = ('input',)
        cmds += __shred_sqlite_char_columns('moz_inputhistory',
                                            cols, input_suffix, path)

    # delete the whole moz_hosts table
    # Reference: https://bugzilla.mozilla.org/show_bug.cgi?id=932036
    # Reference:
    # https://support.mozilla.org/en-US/questions/937290#answer-400987
    if _sqlite_table_exists(path, 'moz_hosts'):
        cmds += __shred_sqlite_char_columns('moz_hosts', ('host',), path=path)
        cmds += "delete from moz_hosts;"

    # execute the commands
    FileUtilities.execute_sqlite3(path, cmds)


def delete_mozilla_favicons(path):
    """Delete favorites icons in Mozilla places.favicons

    Bookmarks are not deleted."""

    def remove_path_from_url(url):
        url = urlparse(url.lstrip('fake-favicon-uri:'))
        return urlunparse((url.scheme, url.netloc, '', '', '', ''))

    cmds = ""

    places_path = os.path.join(os.path.dirname(path), 'places.sqlite')
    cmds += f'attach database "{places_path}" as places;'

    bookmarked_urls_query = ("select url from {db}moz_places where id in "
                             "(select distinct fk from {db}moz_bookmarks "
                             "where fk is not null){filter}")

    # delete all not bookmarked pages with icons
    urls_where = f"where page_url not in ({bookmarked_urls_query.format(db='places.', filter='')})"
    cmds += __shred_sqlite_char_columns('moz_pages_w_icons',
                                        ('page_url',), urls_where, path)

    # delete all not bookmarked icons to pages mapping
    mapping_where = "where page_id not in (select id from moz_pages_w_icons)"
    cmds += __shred_sqlite_char_columns('moz_icons_to_pages',
                                        where=mapping_where, path=path)

    # This intermediate cleaning is needed for the next query to favicons
    # db which collects icon ids that don't have a bookmark or have domain
    # level bookmark.
    FileUtilities.execute_sqlite3(path, cmds)

    # Collect favicons that are not bookmarked with their full url,
    # which collects also domain level bookmarks.
    id_and_url_pairs = _get_sqlite_values(path,
                                          "select id, icon_url from moz_icons where "
                                          "(id not in (select icon_id from moz_icons_to_pages))")

    # We query twice the bookmarked urls and this is a kind of
    # duplication. This is because the first usage of bookmarks
    # is for refining further queries to favicons db and if we
    # first extract the bookmarks as a Python list and give them
    # to the query we could cause an error in execute_sqlite3 since
    # it splits the cmds string by ';' and bookmarked url could
    # contain a ';'. Also if we have a Python list with urls we
    # need to pay attention to escaping JavaScript strings in some
    # bookmarks and probably other things. So the safer way for now
    # is to not compose a query with Python list of extracted urls.

    def row_factory(_cursor, row):
        return row[0]
    # With the row_factory bookmarked_urls is a list of urls, instead
    # of list of tuples with first element a url
    bookmarked_urls = _get_sqlite_values(places_path,
                                         bookmarked_urls_query.format(
                                             db='', filter=" and url NOT LIKE 'javascript:%'"),
                                         row_factory)

    bookmarked_urls_domains = list(map(remove_path_from_url, bookmarked_urls))
    ids_to_delete = [id for id, url in id_and_url_pairs
                     if (
                         # Collect only favicons with not bookmarked
                         # urls with same domain or their domain is a
                         # part of a bookmarked url but the favicons are
                         # not domain level. In other words, collect all
                         # that are not bookmarked.
                         remove_path_from_url(url) not in bookmarked_urls_domains or
                         urlparse(url).path.count('/') > 1
                     )
                     ]

    # delete all not bookmarked icons
    icons_where = f"where (id in ({str(ids_to_delete).replace('[', '').replace(']', '')}))"
    cols = ('icon_url', 'data')
    cmds += __shred_sqlite_char_columns('moz_icons', cols, icons_where, path)

    FileUtilities.execute_sqlite3(path, cmds)


def delete_ooo_history(path):
    """Erase the OpenOffice.org MRU in Common.xcu.  No longer valid in Apache OpenOffice.org 3.4."""
    dom1 = xml.dom.minidom.parse(path)
    changed = False
    for node in dom1.getElementsByTagName("node"):
        if node.hasAttribute("oor:name"):
            if "History" == node.getAttribute("oor:name"):
                node.parentNode.removeChild(node)
                node.unlink()
                changed = True
                break
    if changed:
        dom1.writexml(open(path, "w", encoding='utf-8'))


def get_chrome_bookmark_ids(history_path):
    """Given the path of a history file, return the ids in the
    urls table that are bookmarks"""
    bookmark_path = os.path.join(os.path.dirname(history_path), 'Bookmarks')
    if not os.path.exists(bookmark_path):
        return []
    urls = get_chrome_bookmark_urls(bookmark_path)
    ids = []
    for url in urls:
        ids += get_sqlite_int(
            history_path, 'select id from urls where url=?', (url,))
    return ids


def get_chrome_bookmark_urls(path):
    """Return a list of bookmarked URLs in Google Chrome/Chromium"""
    # read file to parser
    with open(path, 'r', encoding='utf-8') as f:
        js = json.load(f)

    # empty list
    urls = []

    # local recursive function
    def get_chrome_bookmark_urls_helper(node):
        if not isinstance(node, dict):
            return
        if 'type' not in node:
            return
        if node['type'] == "folder":
            # folders have children
            for child in node['children']:
                get_chrome_bookmark_urls_helper(child)
        if node['type'] == "url" and 'url' in node:
            urls.append(node['url'])

    # find bookmarks
    for node in js['roots']:
        get_chrome_bookmark_urls_helper(js['roots'][node])

    return list(set(urls))  # unique
