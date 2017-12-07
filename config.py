# edit the URI below to add your RDS password and your AWS URL
# The other elements are the same as used in the tutorial
# format: (user):(password)@(db_identifier).amazonaws.com:3306/(db_name)

SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://cyberwebapp:cyberwebapp@cyber.cxtcolvgp1ec.us-east-2.rds.amazonaws.com/cyber'

# Uncomment the line below if you want to work with a local DB
#SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'

SQLALCHEMY_POOL_RECYCLE = 3600

WTF_CSRF_ENABLED = True
SECRET_KEY = 'oMtcjdyLlF+6LSGju/HxdzyIl1WiPl2UxFvP2vOj'
