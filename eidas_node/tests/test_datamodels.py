from collections import OrderedDict
from enum import Enum
from typing import Optional

from django.test import SimpleTestCase
from lxml.etree import Element, ElementTree, SubElement

from eidas_node.datamodels import (DataModel, XMLDataModel, convert_field_name_to_tag_name,
                                   convert_tag_name_to_field_name)
from eidas_node.errors import ValidationError
from eidas_node.xml import dump_xml, parse_xml


class MyName(DataModel):  # pragma: no cover
    FIELDS = ['first_name', 'last_name']
    first_name = None  # type: str
    last_name = None  # type: str

    def validate(self) -> None:
        pass


class MyUser(DataModel):  # pragma: no cover
    FIELDS = ['name', 'age']
    name = None  # type: MyName
    age = None  # type: int

    def validate(self) -> None:
        pass


def get_user(first_name: str = 'Joe', last_name: str = 'Tester', age: int = 18):
    return MyUser(name=MyName(first_name=first_name, last_name=last_name), age=age)


class TestDataModel(SimpleTestCase):
    def test_construct_without_fields_list(self):
        class ModelWithoutFields(DataModel):  # pragma: no cover
            def validate(self) -> None:
                pass

        self.assertRaisesMessage(TypeError, 'must define FIELDS class attribute', ModelWithoutFields)

    def test_construct_empty(self):
        model = MyUser()
        for name in ['name', 'age']:
            self.assertIsNone(getattr(model, name))

    def test_construct_invalid_field(self):
        self.assertRaises(TypeError, MyUser, country='CZ')

    def test_construct_all_fields(self):
        model = get_user()
        self.assertEqual(model.age, 18)
        self.assertIsInstance(model.name, MyName)
        self.assertEqual(model.name.first_name, 'Joe')
        self.assertEqual(model.name.last_name, 'Tester')

    def test_construct_field_without_default(self):

        class ModelWithoutDefaultValue(DataModel):  # pragma: no cover
            FIELDS = ['name', 'age']
            name = None

            def validate(self) -> None:
                pass

        self.assertRaisesMessage(TypeError, "missing keyword argument 'age'", ModelWithoutDefaultValue)

        model = ModelWithoutDefaultValue(age=18)
        self.assertEqual(getattr(model, 'age'), 18)

    def test_equal_with_same_models(self):
        model = get_user()
        self.assertEqual(model, get_user())
        self.assertNotEqual(model, get_user(age=19))  # outer field
        self.assertNotEqual(model, get_user(first_name='Billy'))  # inner field

    def test_equal_with_same_fields(self):

        class MyName2(DataModel):  # pragma: no cover
            FIELDS = ['first_name', 'last_name']
            first_name = None  # type: str
            last_name = None  # type: str

            def validate(self) -> None:
                pass

        data = {'first_name': 'Bill', 'last_name': 'Gates'}
        self.assertNotEqual(MyName(**data), MyName2(**data))

    def test_equal_wrong_type(self):
        self.assertNotEqual(MyName(first_name='Bill', last_name='Gates'), ('Bill', 'Gates'))

    def test_get_data_as_tuple(self):
        self.assertEqual(get_user().get_data_as_tuple(), (('Joe', 'Tester'), 18))

    def test_get_data_as_dict(self):
        expected = OrderedDict([('name', OrderedDict([('first_name', 'Joe'), ('last_name', 'Tester')])), ('age', 18)])
        self.assertEqual(get_user().get_data_as_dict(), expected)

    def test_iter(self):
        self.assertEqual(tuple(get_user()), (MyName(first_name='Joe', last_name='Tester'), 18))

    def test_str(self):
        self.assertEqual(str(get_user()), "MyUser(name=MyName(first_name='Joe', last_name='Tester'), age=18)")

    def test_repr(self):
        self.assertEqual(repr(get_user()), "MyUser(name=MyName(first_name='Joe', last_name='Tester'), age=18)")

    def test_validate_fields_required(self):
        # All fields invalid (None), the first one raised
        model = MyUser()
        with self.assertRaises(ValidationError) as cm:
            model.validate_fields(int, 'age', 'name', required=True)
        self.assertEqual(cm.exception.args[0], {'age': 'Must be int, not NoneType.'})

        # The first field valid, the second invalid (None) and raised
        model.age = 18
        with self.assertRaises(ValidationError) as cm:
            model.validate_fields(int, 'age', 'name', required=True)
        self.assertEqual(cm.exception.args[0], {'name': 'Must be int, not NoneType.'})

        # The first field valid, the second invalid (but not None) and raised
        model = get_user()
        with self.assertRaises(ValidationError) as cm:
            model.validate_fields(int, 'age', 'name', required=True)
        self.assertEqual(cm.exception.args[0], {'name': 'Must be int, not MyName.'})

        # Treat empty string as None
        with self.assertRaises(ValidationError) as cm:
            MyName(first_name='').validate_fields(str, 'first_name', required=True)
        self.assertEqual(cm.exception.args[0], {'first_name': 'Must be str, not NoneType.'})

        # All fields valid
        get_user().name.validate_fields(str, 'first_name', 'last_name', required=True)

    def test_validate_fields_optional(self):
        # All fields empty
        model = MyUser()
        model.validate_fields(int, 'age', 'name', required=False)

        # The first field valid, the second invalid (but not None) and raised
        model = get_user()
        with self.assertRaises(ValidationError) as cm:
            model.validate_fields(int, 'age', 'name', required=False)
        self.assertEqual(cm.exception.args[0], {'name': 'Must be int or None, not MyName.'})

        # Treat empty string as None
        MyName(first_name='').validate_fields(str, 'first_name', required=False)

        # All fields valid
        get_user().name.validate_fields(str, 'first_name', 'last_name', required=False)


class MyXMLModel(XMLDataModel):  # pragma: no cover
    FIELDS = ['name']
    name = None

    def validate(self) -> None:
        pass


class Department(Enum):
    TECH_DEP = 'TechDep'
    ADMINS = 'Admins'


class XMLName(XMLDataModel):  # pragma: no cover
    ROOT_ELEMENT = 'name'
    FIELDS = ['first_name', 'last_name']
    first_name = None  # type: str
    last_name = None  # type: str

    def validate(self) -> None:
        pass

    def serialize_last_name(self, parent_element: Element, tag: str, value: str) -> None:
        SubElement(parent_element, tag).text = value.capitalize()

    def deserialize_last_name(self, elm: Element) -> str:
        return elm.text.upper()


class XMLUser(XMLDataModel):  # pragma: no cover
    ROOT_ELEMENT = 'xmlUser'
    FIELDS = ['name', 'superuser', 'department', 'nickname']
    name = None  # type: MyName
    superuser = None  # type: bool
    department = None  # type: Department
    nickname = None  # type: Optional[str]

    def validate(self) -> None:
        pass

    def deserialize_name(self, elm: Element) -> XMLName:
        return XMLName.load_xml(elm)

    def deserialize_department(self, elm: Element) -> Optional[Department]:
        return Department(elm.text) if elm.text else None

    def deserialize_superuser(self, elm: Element) -> Optional[bool]:
        return elm.text == 'true' if elm.text else None


XML_USER_DATA = '''<?xml version='1.0' encoding='utf-8' standalone='yes'?>
<xmlUser>
  <name>
    <firstName>John</firstName>
    <lastName>Doe</lastName>
  </name>
  <superuser>true</superuser>
  <department>TechDep</department>
</xmlUser>
'''


class TestXMLDataModel(SimpleTestCase):
    def test_load_xml_without_root_element_name(self):
        self.assertRaisesMessage(TypeError, 'must define ROOT_ELEMENT',
                                 MyXMLModel.load_xml, ElementTree(Element('root')))

    def test_load_xml_ok(self):
        user = XMLUser(name=XMLName(first_name='John', last_name='DOE'),
                       superuser=True, department=Department.TECH_DEP)
        self.assertEqual(XMLUser.load_xml(parse_xml(XML_USER_DATA)), user)

    def test_load_xml_wrong_root_element(self):
        with self.assertRaisesMessage(ValidationError, '\'<user>\': "Invalid root element \'user\'."'):
            XMLUser.load_xml(parse_xml(XML_USER_DATA.replace('xmlUser', 'user')))

    def test_load_xml_wrong_field_element(self):
        with self.assertRaisesMessage(ValidationError,
                                      '\'<xmlUser><name><familyName>\': "Unknown element \'familyName\'."'):
            XMLUser.load_xml(parse_xml(XML_USER_DATA.replace('lastName', 'familyName')))

    def test_export_xml_without_root_element_name(self):
        self.assertRaisesMessage(TypeError, 'must define ROOT_ELEMENT', MyXMLModel().export_xml)

    def test_export_xml_ok(self):
        self.maxDiff = None
        user = XMLUser(name=XMLName(first_name='John', last_name='Doe'),
                       superuser=True, department=Department.TECH_DEP)
        self.assertEqual(dump_xml(user.export_xml()).decode('utf8'), XML_USER_DATA)


class TestNameConversion(SimpleTestCase):
    def test_convert_tag_name_to_field_name(self):
        self.assertEqual(convert_tag_name_to_field_name('nameIdFormat'), 'name_id_format')

    def test_convert_field_name_to_tag_name(self):
        self.assertEqual(convert_field_name_to_tag_name('name_id_format'), 'nameIdFormat')
