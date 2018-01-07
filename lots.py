from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
 
from models import Base, Category, Items, User
 
engine = create_engine('sqlite:///catalog_app.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine
 
DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()



cat1=Category(name='Soccer')
cat2=Category(name='Basketball')
cat3=Category(name='Baseball')
cat4=Category(name='Frisbee')
cat5=Category(name='Snowboarding')
cat6=Category(name='Rock Climbing')
cat7=Category(name='Foosball')
cat8=Category(name='Skating')
cat9=Category(name='Hockey')

session.add(cat1)
session.add(cat2)
session.add(cat3)
session.add(cat4)
session.add(cat5)
session.add(cat6)
session.add(cat7)
session.add(cat8)
session.add(cat9)


item1=Items(name='jersey',category=cat1,description='dsfdsfdsfdsfdsfdsfdsfsdfdsf')
item2=Items(name='short',category=cat1)
item3=Items(name='footwear',category=cat1)


item4=Items(name='goggles',category=cat2)
item5=Items(name='basketball ',category=cat2)
item6=Items(name='socks',category=cat2)

item7=Items(name='glove',category=cat3)
item8=Items(name='baseball cleats ',category=cat3)


item9=Items(name='disc golf',category=cat4)
item10=Items(name='flying discs',category=cat4)

item11=Items(name='snowboard',category=cat5)



item12=Items(name='protection bolts',category=cat6)


session.add(item1)
session.add(item2)
session.add(item3)
session.add(item4)
session.add(item5)
session.add(item6)
session.add(item7)
session.add(item8)
session.add(item9)
session.add(item10)
session.add(item11)
session.add(item12)

session.commit()





print session.query(Category).all()
