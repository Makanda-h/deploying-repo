from flask_restful import Api, Resource, reqparse
from sqlalchemy.orm import joinedload
from flask import request, jsonify
from models import db, User, Student, Teacher, Course, Enrollment
from schemas import (user_schema, student_schema, teacher_schema, 
                     course_schema, enrollment_schema, ValidationError,
                     validate_user_data, validate_student_data, 
                     validate_teacher_data, validate_course_data, 
                     validate_enrollment_data)
from flask_jwt_extended import jwt_required, create_access_token, get_jwt_identity, get_jwt
from auth import role_required

api = Api()

class UserRegistration(Resource):
    def post(self):
        data = request.get_json()
        try:
            validate_user_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        if User.query.filter_by(username=data['username']).first():
            return {'message': 'User already exists'}, 400
        
        new_user = User(username=data['username'], email=data['email'], role=data['role'])
        new_user.set_password(data['password'])
        db.session.add(new_user)
        db.session.commit()
        
        return {'message': 'User created successfully'}, 201

class UserLogin(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and user.check_password(data['password']):
            access_token = create_access_token(identity=user)
            return {'access_token': access_token}, 200
        return {'message': 'Invalid credentials'}, 401

class UserResource(Resource):
    @jwt_required()
    @role_required('admin')
    def get(self, user_id=None):
        if user_id:
            user = User.query.get_or_404(user_id)
            return user_schema.dump(user)
        users = User.query.all()
        return user_schema.dump(users, many=True)

    @jwt_required()
    @role_required('admin')
    def put(self, user_id):
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        try:
            # to Validate only the fields that are present
            validate_user_data({k: v for k, v in data.items() if k != 'password'})
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        for field in ['username', 'email', 'role']:
            if field in data:
                setattr(user, field, data[field])
        
        if 'password' in data:
            user.set_password(data['password'])
        
        db.session.commit()
        return {'message': 'User updated successfully'}

    @jwt_required()
    @role_required('admin')
    def delete(self, user_id):
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        return {'message': 'User deleted successfully'}

class StudentResource(Resource):
    @jwt_required()
    @role_required('admin', 'teacher')
    def get(self, student_id=None):
        if student_id:
            student = Student.query.get_or_404(student_id)
            return student_schema.dump(student)
        students = Student.query.all()
        return student_schema.dump(students, many=True)
    @jwt_required()
    @role_required('admin')
    def post(self):
        data = request.get_json()
        try:
            validate_student_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        user = User.query.get(data['user_id'])
        if not user:
            return {'message': 'Associated user not found'}, 404
        
        new_student = Student(
            user_id=data['user_id'],
            student_id=data['student_id'],
            name=user.username,
            email=user.email
        )
        db.session.add(new_student)
        db.session.commit()
        return {'message': 'Student created successfully'}, 201
    @jwt_required()
    @role_required('admin')
    def put(self, student_id):
        student = Student.query.get_or_404(student_id)
        data = request.get_json()
        try:
            validate_student_data(data, partial=True)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        if 'student_id' in data:
            student.student_id = data['student_id']
        if 'name' in data:
            student.name = data['name']
        if 'email' in data:
            student.email = data['email']
        
        db.session.commit()
        return {'message': 'Student updated successfully'}
    @jwt_required()
    @role_required('admin')
    def delete(self, student_id):
        student = Student.query.get_or_404(student_id)
        db.session.delete(student)
        db.session.commit()
        return {'message': 'Student deleted successfully'}
    
    @jwt_required()
    @role_required('admin', 'teacher')
    def get(self, student_id=None):
        if student_id:
            student = Student.query.get_or_404(student_id)
            return student_schema.dump(student)
        students = Student.query.all()
        return student_schema.dump(students, many=True)

    @jwt_required()
    @role_required('admin')
    def post(self):
        data = request.get_json()
        try:
            validate_student_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        # Fetch the associated user to get name and email
        user = User.query.get(data['user_id'])
        if not user:
            return {'message': 'Associated user not found'}, 404
        
        new_student = Student(
            user_id=data['user_id'],
            student_id=data['student_id'],
            name=user.username,  # Using username as name
            email=user.email
        )
        db.session.add(new_student)
        db.session.commit()
        return {'message': 'Student created successfully'}, 201

    @jwt_required()
    @role_required('admin')
    def put(self, teacher_id):
        teacher = Teacher.query.get_or_404(teacher_id)
        data = request.get_json()
        try:
            validate_teacher_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        for key, value in data.items():
            setattr(teacher, key, value)
        db.session.commit()
        return {'message': 'Teacher updated successfully'}

    @jwt_required()
    @role_required('admin')
    def delete(self, student_id):
        student = Student.query.get_or_404(student_id)
        db.session.delete(student)
        db.session.commit()
        return {'message': 'Student deleted successfully'}
    
class TeacherResource(Resource):
    @jwt_required()
    @role_required('admin')
    def get(self, teacher_id=None):
        if teacher_id:
            teacher = Teacher.query.get_or_404(teacher_id)
            return teacher_schema.dump(teacher)
        teachers = Teacher.query.all()
        return teacher_schema.dump(teachers, many=True)

    @jwt_required()
    @role_required('admin')
    def post(self):
        data = request.get_json()
        try:
            validate_teacher_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        user = User.query.get(data['user_id'])
        if not user:
            return {'message': 'Associated user not found'}, 404
        
        new_teacher = Teacher(
            user_id=data['user_id'],
            teacher_id=data['teacher_id'],
            name=user.username,  # Using username as name
            email=user.email
        )
        db.session.add(new_teacher)
        db.session.commit()
        return {'message': 'Teacher created successfully'}, 201

    @jwt_required()
    @role_required('admin')
    def put(self, teacher_id):
        teacher = Teacher.query.get_or_404(teacher_id)
        data = request.get_json()
        try:
            validate_teacher_data(data, partial=True)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        if 'teacher_id' in data:
            teacher.teacher_id = data['teacher_id']
        if 'name' in data:
            teacher.name = data['name']
        if 'email' in data:
            teacher.email = data['email']
        
        db.session.commit()
        return {'message': 'Teacher updated successfully'}

    @jwt_required()
    @role_required('admin')
    def delete(self, teacher_id):
        teacher = Teacher.query.options(joinedload('course_teachers')).get_or_404(teacher_id)
        
        try:
           
            for course_teacher in teacher.course_teachers:
                db.session.delete(course_teacher)
            
            db.session.delete(teacher)
            db.session.commit()
            return {'message': 'Teacher deleted successfully'}
        except Exception as e:
            db.session.rollback()
            return {'message': 'An error occurred while deleting the teacher', 'error': str(e)}, 500

    
    @jwt_required()
    @role_required('admin')
    def get(self, teacher_id=None):
        if teacher_id:
            teacher = Teacher.query.get_or_404(teacher_id)
            return teacher_schema.dump(teacher)
        teachers = Teacher.query.all()
        return teacher_schema.dump(teachers, many=True)

    @jwt_required()
    @role_required('admin')
    def post(self):
        data = request.get_json()
        try:
            validate_teacher_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        user = User.query.get(data['user_id'])
        if not user:
            return {'message': 'Associated user not found'}, 404
        
        new_teacher = Teacher(
            user_id=data['user_id'],
            teacher_id=data['teacher_id'],
            name=user.username if user.username else None,
            email=user.email if user.email else None
        )
        db.session.add(new_teacher)
        db.session.commit()
        return {'message': 'Teacher created successfully'}, 201

    @jwt_required()
    @role_required('admin')
    def put(self, teacher_id):
        teacher = Teacher.query.get_or_404(teacher_id)
        data = request.get_json()
        try:
            validate_teacher_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        teacher.teacher_id = data['teacher_id']
        db.session.commit()
        return {'message': 'Teacher updated successfully'}

    @jwt_required()
    @role_required('admin')
    def delete(self, teacher_id):
        teacher = Teacher.query.get_or_404(teacher_id)
        db.session.delete(teacher)
        db.session.commit()
        return {'message': 'Teacher deleted successfully'}

class CourseResource(Resource):
    @jwt_required()
    @role_required('admin', 'teacher', 'student')
    def get(self, course_id=None):
        if course_id:
            course = Course.query.get_or_404(course_id)
            return course_schema.dump(course)
        courses = Course.query.all()
        return course_schema.dump(courses, many=True)

    @jwt_required()
    @role_required('admin')
    def post(self):
        data = request.get_json()
        try:
            validate_course_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        new_course = Course(course_name=data['course_name'], course_code=data['course_code'])
        
        if 'teacher_ids' in data and isinstance(data['teacher_ids'], list):
            teachers = Teacher.query.filter(Teacher.id.in_(data['teacher_ids'])).all()
            new_course.teachers.extend(teachers)
        elif 'teacher_id' in data:
            teacher = Teacher.query.get(data['teacher_id'])
            if teacher:
                new_course.teachers.append(teacher)
        
        db.session.add(new_course)
        db.session.commit()
        return {'message': 'Course created successfully'}, 201

    @jwt_required()
    @role_required('admin')
    def put(self, course_id):
        course = Course.query.get_or_404(course_id)
        data = request.get_json()
        try:
            validate_course_data(data, partial=True)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        
        if 'course_name' in data:
            course.course_name = data['course_name']
        if 'course_code' in data:
            course.course_code = data['course_code']
        if 'teacher_ids' in data and isinstance(data['teacher_ids'], list):
            teachers = Teacher.query.filter(Teacher.id.in_(data['teacher_ids'])).all()
            course.teachers = teachers
        elif 'teacher_id' in data:
            teacher = Teacher.query.get(data['teacher_id'])
            if teacher:
                course.teachers = [teacher]
        
        db.session.commit()
        return {'message': 'Course updated successfully'}

    @jwt_required()
    @role_required('admin')
    def delete(self, course_id):
        course = Course.query.options(joinedload(Course.course_teachers)).get_or_404(course_id)
        
        try:
            # Delete associated CourseTeacher records
            for ct in course.course_teachers:
                db.session.delete(ct)
            
            # Now delete the course
            db.session.delete(course)
            db.session.commit()
            return {'message': 'Course deleted successfully'}
        except Exception as e:
            db.session.rollback()
            return {'message': 'An error occurred while deleting the course', 'error': str(e)}, 500

class EnrollmentResource(Resource):
    @jwt_required()
    @role_required('admin', 'teacher', 'student')
    def get(self, enrollment_id=None):
        claims = get_jwt()
        user_id = get_jwt_identity()
        user_role = claims.get('role')
        if enrollment_id:
            enrollment = Enrollment.query.options(
                joinedload(Enrollment.student).joinedload(Student.user),
                joinedload(Enrollment.course).joinedload(Course.teachers)
            ).get_or_404(enrollment_id)
            
            if user_role == 'student' and enrollment.student.user_id != user_id:
                return {'message': 'Unauthorized'}, 403
            elif user_role == 'teacher':
                teacher = Teacher.query.filter_by(user_id=user_id).first()
                if not teacher or teacher not in enrollment.course.teachers:
                    return {'message': 'Unauthorized'}, 403
            
            return enrollment_schema.dump(enrollment)
        if user_role == 'admin':
            enrollments = Enrollment.query.options(
                joinedload(Enrollment.student),
                joinedload(Enrollment.course)
            ).all()
        elif user_role == 'teacher':
            teacher = Teacher.query.filter_by(user_id=user_id).first()
            if not teacher:
                return {'message': 'Teacher not found'}, 404
            enrollments = Enrollment.query.join(Enrollment.course).filter(Course.teachers.contains(teacher)).all()
        elif user_role == 'student':
            student = Student.query.filter_by(user_id=user_id).first()
            if not student:
                return {'message': 'Student not found'}, 404
            enrollments = student.enrollments
        return enrollment_schema.dump(enrollments, many=True)

    @jwt_required()
    @role_required('admin', 'teacher')
    def post(self):
        data = request.get_json()
        try:
            validate_enrollment_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        new_enrollment = Enrollment(student_id=data['student_id'], course_id=data['course_id'])
        db.session.add(new_enrollment)
        db.session.commit()
        return {'message': 'Enrollment created successfully'}, 201

    @jwt_required()
    @role_required('admin', 'teacher')
    def put(self, enrollment_id):
        claims = get_jwt()
        user_id = get_jwt_identity()
        user_role = claims.get('role')

        enrollment = Enrollment.query.get_or_404(enrollment_id)
        
        if user_role == 'teacher':
            teacher = Teacher.query.filter_by(user_id=user_id).first()
            if not teacher or enrollment.course not in teacher.courses:
                return {'message': 'Unauthorized'}, 403

        data = request.get_json()
        try:
            validate_enrollment_data(data)
        except ValidationError as err:
            return {'errors': err.messages}, 400
        enrollment.grade = data['grade']
        db.session.commit()
        return {'message': 'Grade updated successfully'}

    @jwt_required()
    @role_required('admin')
    def delete(self, enrollment_id):
        enrollment = Enrollment.query.get_or_404(enrollment_id)
        db.session.delete(enrollment)
        db.session.commit()
        return {'message': 'Enrollment deleted successfully'}

api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(StudentResource, '/students', '/students/<int:student_id>')
api.add_resource(TeacherResource, '/teachers', '/teachers/<int:teacher_id>')
api.add_resource(CourseResource, '/courses', '/courses/<int:course_id>')
api.add_resource(EnrollmentResource, '/enrollments', '/enrollments/<int:enrollment_id>')