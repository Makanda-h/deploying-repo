from marshmallow import Schema, fields, validate, ValidationError

class UserSchema(Schema):
    id = fields.Integer(dump_only=True)
    username = fields.String(required=True, validate=validate.Length(min=3, max=80))
    email = fields.Email(required=True)
    role = fields.String(required=True, validate=validate.OneOf(['admin', 'teacher', 'student']))
    password = fields.String(required=True, load_only=True, validate=validate.Length(min=6))

class TeacherSchema(Schema):
    id = fields.Integer(dump_only=True)
    user_id = fields.Integer()  # Remove required=True
    teacher_id = fields.String(validate=validate.Length(min=3, max=20))  # Remove required=True
    name = fields.String(validate=validate.Length(min=1, max=100))
    email = fields.Email()
    user = fields.Nested(UserSchema, exclude=('password',))

class StudentSchema(Schema):
    id = fields.Integer(dump_only=True)
    user_id = fields.Integer(required=True)
    student_id = fields.String(required=True, validate=validate.Length(min=3, max=20))
    name = fields.String(validate=validate.Length(min=1, max=100))
    email = fields.Email()
    user = fields.Nested(UserSchema, exclude=('password',))

class CourseSchema(Schema):
    id = fields.Integer(dump_only=True)
    course_name = fields.String(required=True, validate=validate.Length(min=3, max=100))
    course_code = fields.String(required=True, validate=validate.Length(min=3, max=20))
    teachers = fields.Nested(TeacherSchema, many=True, dump_only=True)
    teacher_id = fields.Integer(load_only=True)  # For backward compatibility
    teacher_ids = fields.List(fields.Integer(), load_only=True)

class EnrollmentSchema(Schema):
    id = fields.Integer(dump_only=True)
    student_id = fields.Integer(required=True)
    course_id = fields.Integer(required=True)
    grade = fields.Float(validate=validate.Range(min=0, max=100))
    student = fields.Nested(StudentSchema)  # Remove any exclude parameter here
    course = fields.Nested(CourseSchema, exclude=('enrollments', 'teachers'))

# Create instances of schemas
user_schema = UserSchema()
student_schema = StudentSchema()
teacher_schema = TeacherSchema()
course_schema = CourseSchema()
enrollment_schema = EnrollmentSchema()

def validate_user_data(data, partial=False):
    schema = UserSchema(partial=partial)
    errors = schema.validate(data)
    if errors:
        raise ValidationError(errors)

def validate_student_data(data, partial=False):
    schema = StudentSchema(partial=partial)
    errors = schema.validate(data)
    if errors:
        raise ValidationError(errors)

def validate_teacher_data(data, partial=False):
    schema = TeacherSchema(partial=partial)
    errors = schema.validate(data)
    if errors:
        raise ValidationError(errors)

def validate_course_data(data, partial=False):
    schema = CourseSchema(partial=partial)
    errors = schema.validate(data)
    if errors:
        raise ValidationError(errors)
    
def validate_enrollment_data(data, partial=False):
    schema = EnrollmentSchema(partial=partial)
    errors = schema.validate(data)
    if errors:
        raise ValidationError(errors)