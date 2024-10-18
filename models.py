from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.ext.associationproxy import association_proxy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    serialize_rules = ('-password_hash', '-student', '-teacher')

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)

    @validates('role')
    def validate_role(self, key, role):
        if role not in ['admin', 'teacher', 'student']:
            raise ValueError('Invalid role')
        return role

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class CourseTeacher(db.Model):
    __tablename__ = 'course_teachers'
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), primary_key=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('teachers.id'), primary_key=True)

class Course(db.Model, SerializerMixin):
    __tablename__ = 'courses'
    serialize_rules = ('-teachers.courses', '-enrollments.course')
    id = db.Column(db.Integer, primary_key=True)
    course_name = db.Column(db.String(100), nullable=False)
    course_code = db.Column(db.String(20), unique=True, nullable=False)
    teachers = db.relationship('Teacher', secondary='course_teachers', back_populates='courses')
    enrollments = db.relationship('Enrollment', back_populates='course', cascade='all, delete-orphan')

    @validates('course_name', 'course_code')
    def validate_course(self, key, value):
        if not value or len(value) < 3:
            raise ValueError(f'{key} must be at least 3 characters long')
        return value

class Teacher(db.Model, SerializerMixin):
    __tablename__ = 'teachers'
    serialize_rules = ('-courses.teachers', '-user.teacher')
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    teacher_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    user = db.relationship('User', backref=db.backref('teacher', uselist=False))
    courses = db.relationship('Course', secondary='course_teachers', back_populates='teachers')

    @validates('teacher_id')
    def validate_teacher_id(self, key, teacher_id):
        if not teacher_id or len(teacher_id) < 3:
            raise ValueError('Teacher ID must be at least 3 characters long')
        return teacher_id

class Student(db.Model, SerializerMixin):
    __tablename__ = 'students'
    serialize_rules = ('-user.student', '-courses.students', '-enrollments.student')
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    user = db.relationship('User', backref=db.backref('student', uselist=False))
    enrollments = db.relationship('Enrollment', back_populates='student', cascade='all, delete-orphan')
    
    @validates('student_id')
    def validate_student_id(self, key, student_id):
        if not student_id or len(student_id) < 3:
            raise ValueError('Student ID must be at least 3 characters long')
        return student_id

class Enrollment(db.Model, SerializerMixin):
    __tablename__ = 'enrollments'
    serialize_rules = ('-student.enrollments', '-course.enrollments')

    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    grade = db.Column(db.Float)
    student = db.relationship('Student', back_populates='enrollments')
    course = db.relationship('Course', back_populates='enrollments')

    @validates('grade')
    def validate_grade(self, key, grade):
        if grade is not None and (grade < 0 or grade > 100):
            raise ValueError('Grade must be between 0 and 100')
        return grade