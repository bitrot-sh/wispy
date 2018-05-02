from mongoengine import *
from mongoengine import signals

from datetime import datetime

def update_document(sender, document):
    document.last_seen = datetime.utcnow()

class Event(EmbeddedDocument):
    e_type    = StringField(required=True)
    ssid      = StringField()
    dest      = StringField(required=False)
    timestamp = DateTimeField(default=datetime.utcnow())
    location  = StringField()

    meta = {'allow_inheritance': True}

class Probe(Event):
    e_type    = StringField(default='probe')

class Beacon(Event):
    e_type    = StringField(default='beacon')

class Data(Event):
    e_type    = StringField(default='data')

class Device(Document):
    mac       = StringField(primary_key=True, required=True)
    vendor    = StringField()
    events    = EmbeddedDocumentListField(Event)
    last_seen = DateTimeField()

signals.pre_save.connect(update_document)
