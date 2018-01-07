from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from passlib.apps import custom_app_context as pwd_context
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(250))
    email = Column(String(250),unique=True)
    provider = Column(String(250))
    picture = Column(String(250))
    password_hash = Column(String(250))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

class Items(Base):
    __tablename__='items'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(String)
    category_id = Column(Integer,ForeignKey('category.id'))
    category = relationship("Category", backref="items")
    def serialize(self):
	    """Return object data in easily serializeable format"""
	    return {
                'id' : self.id,
                'name' : self.name
	        }
class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    @property
    def serialize(self):
	"""Return object data in easily serializeable format"""
	return {
            'id' : self.id,
            'name' : self.name
	    }
engine = create_engine('sqlite:///catalog_app.db')
 

Base.metadata.create_all(engine)
