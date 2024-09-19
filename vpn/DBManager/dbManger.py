import mysql.connector
import os

class Db_Server:
    def __init__(self,server,username,password,db_name):
        self.cred = {
            "host":server,
            "user":username,
            "password":password,
            "database":db_name
        }
    
    def name_lister(self):
        try:
            conn = mysql.connector.connect(**self.cred)
            cursr = conn.cursor()
            cursr.execute("SELECT username, password FROM vpn;")
            lst = cursr.fetchall()

            for row in lst:
                print(f"username : {row[0]}\t\tpassword : {row[1]}") 
            
        except mysql.connector.Error as err:
            print(f"Error: {err}")
        
        finally:
            if conn.is_connected():
                cursr.close()
                conn.close()

    def name_searcher(self, name):
        try:
            conn = mysql.connector.connect(**self.cred)
            cursr = conn.cursor()
            
            query = "SELECT username, password FROM vpn WHERE username = %s"
            cursr.execute(query, (name,))
            lst = cursr.fetchone()

            if lst:
                self.clearscn()
                print(f"Username: {lst[0]}\t\tPassword: {lst[1]}")
            else:
                print("Username doesn't exist")
        
        except mysql.connector.Error as err:
            print(f"Error: {err}")
        
        finally:
            if conn:
                if conn.is_connected():
                    cursr.close()
                    conn.close()

    def user_remover(self,username):
        query = "DELETE FROM vpn WHERE username = '{}';".format(username)

        if self.name_searcher(username):
            try:
                conn = mysql.connector.connect(**self.cred)
                cursr = conn.cursor()
                cursr.execute(query)
                print("User dropped successfully")
            except mysql.connector.Error as Error:
                print(Error)
    
    def clearscn(self):
        os.system("clear")
