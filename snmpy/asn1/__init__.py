from typing import Union, SupportsBytes, Optional

from .enums import TagClassEnum, UniversalClassTags

class ObjectTag:
    def __init__(self, tag_class: TagClassEnum, is_constructed: bool, tag_id: Union[UniversalClassTags, int]):
        self.tag_class = tag_class
        self.is_constructed = is_constructed
        self.tag_id = tag_id

    def __bytes__(self):
        raise NotImplementedError()

    def __repr__(self):
        return "(%s,%s,%s)" % (self.tag_class.name,
                               "constructed" if self.is_constructed else "simple",
                               self.tag_id.name if hasattr(self.tag_id, 'name') else self.tag_id)

class Object(type):
    _tag_class_: TagClassEnum = TagClassEnum.universal
    _tag_constructed_: bool = False
    _tag_id_: UniversalClassTags
    _content_: SupportsBytes = None

    def __init__(self, tag: ObjectTag, content: SupportsBytes):

        pass


    def __new__(cls, *args, tag: Optional[ObjectTag], **kwargs):
        if tag is None:
            # TODO: metaclass Object, so that ObjectTag is part of the type/class, not some value passed in--- that way can use the underlying __init__ without problems for the content
            tag = ObjectTag(cls._tag_class_, cls._tag_constructed_, cls._tag_id_)

        cls(*args, **kwargs)


    def __repr__(self):
        return "%s{%s: %s}" % (self.__class__.__name__, self._tag_id_, self.value)

    def __bytes__(self):
        raise NotImplementedError()
