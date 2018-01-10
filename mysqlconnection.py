from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
# Create a class that will give us an object that we can use to connect to a database
class MySQLConnection(object):
    def __init__(self, app, db):
        config = {
                'host': 'localhost',
                'database': db, 
                'user': 'root',
                'password': 'root',
                'port': '3306' 
        }
        # this will use the above values to generate the path to connect to your sql database
        DATABASE_URI = "mysql://{}:{}@127.0.0.1:{}/{}".format(config['user'], config['password'], config['port'], config['database'])
        app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
        # establish the connection to database
        self.db = SQLAlchemy(app)
    # this is the method we will use to query the database
    def query_db(self, query, data=None):
        result = self.db.session.execute(text(query), data)
        print result;
        if query[0:6].lower() == 'select':
            list_result = [dict(r) for r in result]
            return list_result
        elif query[0:6].lower() == 'insert':
            self.db.session.commit()
            return result.lastrowid
        else:
            # if the query was an update or delete, return nothing and commit changes
            self.db.session.commit()

def MySQLConnector(app, db):
    return MySQLConnection(app, db)

