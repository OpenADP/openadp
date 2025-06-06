# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: openadp.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='openadp.proto',
  package='openadp',
  syntax='proto3',
  serialized_pb=_b('\n\ropenadp.proto\x12\x07openadp\"\x8e\x01\n\x15RegisterSecretRequest\x12\x0b\n\x03UID\x18\x01 \x01(\t\x12\x0b\n\x03\x44ID\x18\x02 \x01(\t\x12\x0b\n\x03\x42ID\x18\x03 \x01(\t\x12\x0f\n\x07version\x18\x04 \x01(\x05\x12\t\n\x01x\x18\x05 \x01(\r\x12\t\n\x01y\x18\x06 \x01(\x0c\x12\x13\n\x0bmax_guesses\x18\x07 \x01(\r\x12\x12\n\nexpiration\x18\x08 \x01(\x04\"\x18\n\x16RegisterSecretResponse\"H\n\x14RecoverSecretRequest\x12\x0b\n\x03UID\x18\x01 \x01(\t\x12\x0b\n\x03\x44ID\x18\x02 \x01(\t\x12\x0b\n\x03\x42ID\x18\x03 \x01(\t\x12\t\n\x01\x42\x18\x04 \x01(\x0c\"~\n\x15RecoverSecretResponse\x12\x0f\n\x07version\x18\x01 \x01(\r\x12\t\n\x01x\x18\x02 \x01(\r\x12\x0b\n\x03siB\x18\x03 \x01(\x0c\x12\x13\n\x0b\x62\x61\x64_guesses\x18\x04 \x01(\r\x12\x13\n\x0bmax_guesses\x18\x05 \x01(\r\x12\x12\n\nexpiration\x18\x06 \x01(\x04\x32\xb0\x01\n\x07OpenADP\x12S\n\x0eRegisterSecret\x12\x1e.openadp.RegisterSecretRequest\x1a\x1f.openadp.RegisterSecretResponse\"\x00\x12P\n\rRecoverSecret\x12\x1d.openadp.RecoverSecretRequest\x1a\x1e.openadp.RecoverSecretResponse\"\x00\x62\x06proto3')
)




_REGISTERSECRETREQUEST = _descriptor.Descriptor(
  name='RegisterSecretRequest',
  full_name='openadp.RegisterSecretRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='UID', full_name='openadp.RegisterSecretRequest.UID', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='DID', full_name='openadp.RegisterSecretRequest.DID', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='BID', full_name='openadp.RegisterSecretRequest.BID', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='version', full_name='openadp.RegisterSecretRequest.version', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='x', full_name='openadp.RegisterSecretRequest.x', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='y', full_name='openadp.RegisterSecretRequest.y', index=5,
      number=6, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='max_guesses', full_name='openadp.RegisterSecretRequest.max_guesses', index=6,
      number=7, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='expiration', full_name='openadp.RegisterSecretRequest.expiration', index=7,
      number=8, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=27,
  serialized_end=169,
)


_REGISTERSECRETRESPONSE = _descriptor.Descriptor(
  name='RegisterSecretResponse',
  full_name='openadp.RegisterSecretResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=171,
  serialized_end=195,
)


_RECOVERSECRETREQUEST = _descriptor.Descriptor(
  name='RecoverSecretRequest',
  full_name='openadp.RecoverSecretRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='UID', full_name='openadp.RecoverSecretRequest.UID', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='DID', full_name='openadp.RecoverSecretRequest.DID', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='BID', full_name='openadp.RecoverSecretRequest.BID', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='B', full_name='openadp.RecoverSecretRequest.B', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=197,
  serialized_end=269,
)


_RECOVERSECRETRESPONSE = _descriptor.Descriptor(
  name='RecoverSecretResponse',
  full_name='openadp.RecoverSecretResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='version', full_name='openadp.RecoverSecretResponse.version', index=0,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='x', full_name='openadp.RecoverSecretResponse.x', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='siB', full_name='openadp.RecoverSecretResponse.siB', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='bad_guesses', full_name='openadp.RecoverSecretResponse.bad_guesses', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='max_guesses', full_name='openadp.RecoverSecretResponse.max_guesses', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='expiration', full_name='openadp.RecoverSecretResponse.expiration', index=5,
      number=6, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=271,
  serialized_end=397,
)

DESCRIPTOR.message_types_by_name['RegisterSecretRequest'] = _REGISTERSECRETREQUEST
DESCRIPTOR.message_types_by_name['RegisterSecretResponse'] = _REGISTERSECRETRESPONSE
DESCRIPTOR.message_types_by_name['RecoverSecretRequest'] = _RECOVERSECRETREQUEST
DESCRIPTOR.message_types_by_name['RecoverSecretResponse'] = _RECOVERSECRETRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

RegisterSecretRequest = _reflection.GeneratedProtocolMessageType('RegisterSecretRequest', (_message.Message,), dict(
  DESCRIPTOR = _REGISTERSECRETREQUEST,
  __module__ = 'openadp_pb2'
  # @@protoc_insertion_point(class_scope:openadp.RegisterSecretRequest)
  ))
_sym_db.RegisterMessage(RegisterSecretRequest)

RegisterSecretResponse = _reflection.GeneratedProtocolMessageType('RegisterSecretResponse', (_message.Message,), dict(
  DESCRIPTOR = _REGISTERSECRETRESPONSE,
  __module__ = 'openadp_pb2'
  # @@protoc_insertion_point(class_scope:openadp.RegisterSecretResponse)
  ))
_sym_db.RegisterMessage(RegisterSecretResponse)

RecoverSecretRequest = _reflection.GeneratedProtocolMessageType('RecoverSecretRequest', (_message.Message,), dict(
  DESCRIPTOR = _RECOVERSECRETREQUEST,
  __module__ = 'openadp_pb2'
  # @@protoc_insertion_point(class_scope:openadp.RecoverSecretRequest)
  ))
_sym_db.RegisterMessage(RecoverSecretRequest)

RecoverSecretResponse = _reflection.GeneratedProtocolMessageType('RecoverSecretResponse', (_message.Message,), dict(
  DESCRIPTOR = _RECOVERSECRETRESPONSE,
  __module__ = 'openadp_pb2'
  # @@protoc_insertion_point(class_scope:openadp.RecoverSecretResponse)
  ))
_sym_db.RegisterMessage(RecoverSecretResponse)



_OPENADP = _descriptor.ServiceDescriptor(
  name='OpenADP',
  full_name='openadp.OpenADP',
  file=DESCRIPTOR,
  index=0,
  options=None,
  serialized_start=400,
  serialized_end=576,
  methods=[
  _descriptor.MethodDescriptor(
    name='RegisterSecret',
    full_name='openadp.OpenADP.RegisterSecret',
    index=0,
    containing_service=None,
    input_type=_REGISTERSECRETREQUEST,
    output_type=_REGISTERSECRETRESPONSE,
    options=None,
  ),
  _descriptor.MethodDescriptor(
    name='RecoverSecret',
    full_name='openadp.OpenADP.RecoverSecret',
    index=1,
    containing_service=None,
    input_type=_RECOVERSECRETREQUEST,
    output_type=_RECOVERSECRETRESPONSE,
    options=None,
  ),
])
_sym_db.RegisterServiceDescriptor(_OPENADP)

DESCRIPTOR.services_by_name['OpenADP'] = _OPENADP

# @@protoc_insertion_point(module_scope)
