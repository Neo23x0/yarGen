#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# yarGen DB
#
# Florian Roth

import traceback
import sqlite3 as lite

class YargenDB:

    def __init__(self, string_db, opcode_db):

        # Initialize databases
        try:
            self.string_con = lite.connect(string_db)
            self.opcode_con = lite.connect(opcode_db)
        except lite.Error, e:
            if self.string_con:
                self.string_con.rollback()
            if self.opcode_con:
                self.opcode_con.rollback()
            traceback.print_exc()

    def clear_dbs(self):
        # String DB
        self.clear_db(self.string_con)
        self.clear_db(self.opcode_con)

    def clear_db(self, db):
        try:
            with db:
                cur = db.cursor()
                cur.execute("DROP TABLE IF EXISTS Stats")
                cur.execute("CREATE TABLE Stats(Value TEXT, Count INT)")
                db.commit()
        except lite.Error, e:
            if db:
                db.rollback()
            traceback.print_exc()

    def update_string_db(self, objects):
        count = self.get_table_count(self.string_con)
        print "[+] Updating string database with count %s ..." % count
        self.update_db(objects, self.string_con)
        count = self.get_table_count(self.string_con)
        print "[+] Updated string database to count %s" % count

    def update_opcode_db(self, objects):
        count = self.get_table_count(self.opcode_con)
        print "[+] Updating opcode database with count %s ..." % count
        self.update_db(objects, self.opcode_con)
        count = self.get_table_count(self.opcode_con)
        print "[+] Updated opcode database to count %s" % count

    def update_db(self, objects, db):
        try:
            with db:
                cur = db.cursor()
                # UPDATE
                cur.executemany("INSERT INTO Stats VALUES (?,?);", objects.iteritems())
                db.commit()
        except lite.Error, e:
            if db:
                db.rollback()
            traceback.print_exc()

    def is_good_string(self, string):
        return self.is_value_good(string, self.string_con)

    def is_good_opcode(self, opcode):
        return self.is_value_good(opcode, self.opcode_con)

    def get_string_count(self, string):
        return self.get_value_count(string, self.string_con)

    def get_opcode_count(self, opcode):
        return self.get_value_count(opcode, self.opcode_con)

    def get_table_count(self, db):
        try:
            with db:
                cur = db.cursor()
                cur.execute("SELECT count(*) FROM Stats")
                row = cur.fetchone()
                if row is None:
                    return 0
                else:
                    return row[0]
        except lite.Error, e:
            if db:
                db.rollback()
            traceback.print_exc()

    def is_value_good(self, value, db):
        try:
            with db:
                cur = db.cursor()
                cur.execute("SELECT count(*) FROM Stats WHERE Value = ?", (value,))
                if cur.rowcount > 0:
                    return 1
                else:
                    return 0

        except lite.Error, e:
            if db:
                db.rollback()
            traceback.print_exc()

    def get_value_count(self, value, db):
        try:
            with db:
                cur = db.cursor()
                cur.execute("SELECT sum(Count) FROM Stats WHERE Value = ?;", (value,))
                row = cur.fetchone()
                if row[0] is None:
                    return 0
                else:
                    return row[0]

        except lite.Error, e:
            if db:
                db.rollback()
            traceback.print_exc()

    def get_good_string_matches(self, strings):
        return self.get_good_matches(strings, self.string_con)

    def get_good_opcode_matches(self, opcodes):
        return self.get_good_matches(strings, self.opcode_con)

    def get_good_matches(self, values, db):
        good_values = {}
        try:
            with db:
                cur = db.cursor()
                cur.execute("SELECT * FROM Stats;")
                while True:
                    row = cur.fetchone()
                    if row == None:
                        break
                    if row[0] in values:
                        good_values[row[0]] = row[1]
            return good_values
        except lite.Error, e:
            if db:
                db.rollback()
            traceback.print_exc()