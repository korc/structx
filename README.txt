Crafting packet structures with gui
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Create a example.py file with contents:

--- example.py ---
from packetlib import BasePacketClass, StringSZ, AttrList
class ExamplePacket(BasePacketClass):
	_fields_=AttrList(('data',StringSZ))
--- END ---

Having intersting binary data in some_data_file, run
gui.py example.py:ExamplePacket some_data_file

Start thinking what binary data might mean and add definitions to _fields_
attribute appropriately, then reload the class in gui to see changes.
