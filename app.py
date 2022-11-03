from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow 
from flask_cors import CORS
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import os

# Init app
app = Flask(__name__)

# Database
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'app.sqlite')
db = SQLAlchemy(app)
ma = Marshmallow(app)

# Middleware
bcrypt = Bcrypt(app)
cors = CORS(app)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
jwt = JWTManager(app)



"""
****************************************************************************************************

                                  COMPANY MODEL & SCHEMA

****************************************************************************************************
"""
class Company(db.Model):
      compID = db.Column(db.Integer, primary_key=True)
      compName = db.Column(db.String(50), unique=True, nullable=False)
      compLogo = db.Column(db.String(100), unique=True, nullable=True)
      compPhone = db.Column(db.String(11), unique=True, nullable=False)
      compAddress = db.Column(db.String(100), unique=True, nullable=False)
      compInfo = db.Column(db.String(350), nullable=False)
      compColor = db.Column(db.String(6), unique=False, nullable=True)
      compUsername = db.Column(db.String(50), unique=True, nullable=False)
      compPassword = db.Column(db.String(100), unique=False, nullable=False)
      compEmail = db.Column(db.String(50), unique=True, nullable=False)
      isCompany = db.Column(db.Boolean, default=True)

      def __init__(self, compName, compLogo, compPhone, compAddress, compInfo, compColor, compUsername, compPassword, compEmail, isCompany):
        self.compName = compName
        self.compLogo = compLogo
        self.compPhone = compPhone
        self.compAddress = compAddress
        self.compInfo =  compInfo
        self.compColor = compColor
        self.compUsername = compUsername
        self.compPassword = compPassword
        self.compEmail = compEmail
        self.isCompany = isCompany

class CompanySchema(ma.Schema):
  class Meta:
    fields = ('compID', 'compName', 'compLogo', 'compPhone', 'compInfo', 'compColor', 'compUsername', 'compAddress', 'compEmail', 'isCompany')

company_schema = CompanySchema()
companies_schema = CompanySchema(many=True)

"""
****************************************************************************************************

                                  EMPLOYEE MODEL & SCHEMA

****************************************************************************************************
"""
class Employee(db.Model):
  empID = db.Column(db.Integer, primary_key=True)
  compID = db.Column(db.Integer, db.ForeignKey('company.compID'), nullable=False)
  empLevel = db.Column(db.Integer, nullable=False)
  empFirstName = db.Column(db.String(15), unique=False, nullable=False)
  empLastName = db.Column(db.String(15), unique=False, nullable=False)
  empDOB = db.Column(db.String(10), unique=False, nullable=False)
  titleID = db.Column(db.Integer, db.ForeignKey('title.titleID'))
  empUsername = db.Column(db.String, unique=True, nullable=False)
  empEmail = db.Column(db.String, unique=True, nullable=False)
  empPassword = db.Column(db.String(250), unique=False, nullable=False)
  empStartDate = db.Column(db.String(10), unique=False, nullable=False)
  empEndDate = db.Column(db.String(10), default=None, unique=False, nullable=True)
  empPhone = db.Column(db.String(11), unique=True, nullable=False)
  empPicture = db.Column(db.String(250), unique=False, nullable=True)
  empSalary = db.Column(db.String(10), unique=False, nullable=True)
  empHourly = db.Column(db.String(10), unique=False, nullable=True)
  empStatus = db.Column(db.Boolean, default=True, nullable=False)
  empSSN = db.Column(db.String(9), unique=True, nullable=False)

  def __init__(self, compID, empLevel, empFirstName, empLastName, empDOB, titleID, empUsername, empEmail, empPassword, empStartDate, empEndDate, empPhone, empPicture, empSalary, empHourly, empStatus, empSSN):
    self.compID = compID
    self.empLevel = empLevel
    self.empFirstName = empFirstName
    self.empLastName = empLastName
    self.empDOB = empDOB
    self.titleID = titleID
    self.empUsername = empUsername
    self.empEmail = empEmail
    self.empPassword = empPassword
    self.empStartDate = empStartDate
    self.empEndDate = empEndDate
    self.empPhone = empPhone
    self.empPicture = empPicture
    self.empSalary = empSalary
    self.empHourly = empHourly
    self.empStatus = empStatus
    self.empSSN = empSSN


class EmployeeSchema(ma.Schema):
  class Meta:
    fields = ('empID', 'compID', 'empFirstName', 'empLastName', 'empDOB', 'titleID', 'empUsername', 'empEmail', 'empPassword', 'empStartDate', 'empEndDate', 'empPhone', 'empPicture', 'empSalary', 'empHourly', 'empStatus', 'empLevel', 'empSSN')

employee_schema = EmployeeSchema()
employees_schema = EmployeeSchema(many=True)


"""
****************************************************************************************************

                                  TITLE MODEL & SCHEMA

****************************************************************************************************
"""
# Title Model
class Title(db.Model):
    titleID = db.Column(db.Integer, primary_key=True)
    compID = db.Column(db.Integer, db.ForeignKey('company.compID'), nullable=False)
    empID = db.Column(db.Integer, db.ForeignKey('employee.empID'), nullable=False)
    title = db.Column(db.String(50), unique=False, nullable=False)

    def __init__(self, compID, empID, title):
      self.compID = compID
      self.empID = empID
      self.title = title

# Title Schema
class TitleSchema(ma.Schema):
  class Meta:
    fields = ('compID', 'empID', 'title')

title_schema = TitleSchema()
titles_schema = TitleSchema(many=True)


"""
****************************************************************************************************

                                   PRODUCT MODEL & SCHEMA

****************************************************************************************************
"""
class Product(db.Model):
  productID = db.Column(db.Integer, primary_key=True)
  compID = db.Column(db.Integer, db.ForeignKey('company.compID'), nullable=False)
  prodName = db.Column(db.String(50), unique=False, nullable=False)
  prodDescription = db.Column(db.String(500), unique=False, nullable=False)
  prodPrice = db.Column(db.Float, unique=False, nullable=False)
  prodQuantity = db.Column(db.Integer, unique=False, nullable=False)
  prodImage = db.Column(db.String(250), unique=False, nullable=False)
  prodCategory = db.Column(db.String(50), unique=False, nullable=False)
  prodDate = db.Column(db.DateTime, unique=False, nullable=False, default=datetime.utcnow)

  def __init__(self, compID, prodName, prodDescription, prodPrice, prodQuantity, prodImage, prodCategory, prodDate):
    self.compID = compID
    self.prodName = prodName
    self.prodDescription = prodDescription
    self.prodPrice = prodPrice
    self.prodQuantity = prodQuantity
    self.prodImage = prodImage
    self.prodCategory = prodCategory
    self.prodDate = prodDate

class ProductSchema(ma.Schema):
  class Meta:
    fields = ('productID', 'compID', 'prodName', 'prodDescription', 'prodPrice', 'prodQuantity', 'prodImage', 'prodCategory', 'prodDate')

product_schema = ProductSchema()
products_schema = ProductSchema(many=True)


"""
****************************************************************************************************

                                  ORDER MODEL & SCHEMA

****************************************************************************************************
"""
class Order(db.Model):
  orderID = db.Column(db.Integer, primary_key=True)
  compID = db.Column(db.Integer, db.ForeignKey('company.compID'), unique=False, nullable=False)
  empID = db.Column(db.Integer, db.ForeignKey('employee.empID'), unique=False, nullable=False)
  orderItems = db.Column(db.JSON, unique=False, nullable=False)
  orderTotal = db.Column(db.Float, unique=False, nullable=False)
  orderDate = db.Column(db.DateTime, unique=False, nullable=False, default=datetime.utcnow)

  def __init__(self, compID, empID, orderItems, orderTotal, orderDate):
    self.compID = compID
    self.empID = empID
    self.orderItems = orderItems
    self.orderTotal = orderTotal
    self.orderDate = orderDate

class OrderSchema(ma.Schema):
  class Meta:
    fields = ('orderID', 'compID', 'empID', 'orderItems', 'orderTotal')

order_schema = OrderSchema()
orders_schema = OrderSchema(many=True)


"""
****************************************************************************************************

                                          Helper Functions

****************************************************************************************************
"""
# Duplicate Check
def duplicateCheck(table, column, value):
  if db.session.query(table).filter(column == value).first():
    return True
  else:
    return jsonify({'message': 'Duplicate Entry'}), 400

# Request Content Type Check
def requestContentTypeCheck():
  if request.content_type != 'application/json':
    return jsonify({'message': 'Data must be in JSON format', 'success': False}), 500.19

# Check Authorization (Admin, empLevel 1, Company)
def checkAuthorization(empTitle, empLevel, compID, empID, isCompany):
  if isCompany:
    is_this_company = Company.query.filter_by(compID=compID).first()
    if is_this_company:
      return True

  if empTitle == 'admin' or empLevel == 1:
    company = Company.query.filter_by(compID=compID).first()
    employee_of_company = Employee.query.filter_by(compID=company.compID, empID=empID).first()
    if employee_of_company:
      return True

  else:
    return jsonify({'message': 'Unauthorized', 'success': False}), 401
  

"""
****************************************************************************************************

                                          COMPANY ROUTES 

****************************************************************************************************

@desc: Create Company
@params: compName, compAddress, compPhone, compEmail, compUsername, compPassword
@route: /api/v1/company
@type: PUBLIC
"""
@app.route('/api/v1/company', methods=['POST'])
def create_company():
  requestContentTypeCheck()

  data = request.get_json()
  compName = data.get('compName')
  compLogo = data.get('compLogo')
  compPhone = data.get('compPhone')
  compInfo = data.get('compInfo')
  compColor = data.get('compColor')
  compAddress = data.get('compAddress')
  compEmail = data.get('compEmail')
  compUsername = data.get('compUsername')
  compPassword = data.get('compPassword')
  isCompany = True

  duplicateCheck(Company, Company.compName, compName)
  duplicateCheck(Company, Company.compUsername, compUsername)
  duplicateCheck(Company, Company.compEmail, compEmail)

  
  encrypted_password = bcrypt.generate_password_hash(compPassword).decode('utf-8')
  compPassword = encrypted_password

  new_company = Company(compName, compLogo, compPhone, compAddress, compInfo, compColor, compUsername, compPassword, compEmail, isCompany)

  db.session.add(new_company)
  db.session.commit()

  result = company_schema.dump(new_company)
  company = Company.query.filter_by(compID=result['compID']).first()
  access_token = create_access_token(identity=company_schema.dump(company))
  return jsonify({
    'success': True,
    'message': 'Company Created',
    'data': {
      'company': result,
      'token': access_token
    }
    }), 201

"""
@desc: Get Companies
@params: compID
@route: /api/v1/company
@type: ADMIN
"""
@app.route('/api/v1/company', methods=['GET'])
@jwt_required()
def get_companies():
  all_companies = Company.query.all()
  result = companies_schema.dump(all_companies)
  
  return jsonify({
    'success': True,
    'data': {
      'companies': result
    }
    }), 200

"""
@desc: Delete Company
@params: compID
@route: /api/v1/company
@type: PROTECTED
"""
@app.route('/api/v1/company', methods=['DELETE'])
@jwt_required()
def remove_company():
  requestContentTypeCheck()
  compID = get_jwt_identity()['compID']
  empTitle = get_jwt_identity()['empTitle']
  empLevel = get_jwt_identity()['empLevel']
  empID = get_jwt_identity()['empID']
  isCompany = get_jwt_identity()['isCompany']
  
  if checkAuthorization(empTitle, empLevel, compID, empID, isCompany):
    company = Company.query.filter_by(compID=compID).first()
    employees = Employee.query.filter_by(compID=company.compID).all()
    titles = Title.query.filter_by(compID=company.compID).all()
    products = Product.query.filter_by(compID=company.compID).all()
    orders = Order.query.filter_by(compID=company.compID).all()

    db.session.delete(orders, products, titles, employees, company)
    db.session.commit()
    return jsonify({
        'success': True,
        'message': 'Company & Associated Elements Deleted',
        'data': {}
      }), 200


"""
@desc: Update Company
@params: compID, compName, compLogo, compPhone, compInfo, compColor
@route: /api/v1/company
@type: PROTECTED
"""
@app.route('/api/v1/company', methods=['PUT'])
def update_company():
  requestContentTypeCheck()
  data = request.get_json()
  compID = data.get('compID')
  compName = data.get('compName')
  compLogo = data.get('compLogo')
  compPhone = data.get('compPhone')
  compInfo = data.get('compInfo')
  compColor = data.get('compColor')
  compPassword = data.get('compPassword')
  compNewPassword = data.get('compNewPassword')

  empTitle = get_jwt_identity()['empTitle']
  empCompID = get_jwt_identity()['compID']
  empLevel = get_jwt_identity()['empLevel']
  empID = get_jwt_identity()['empID']
  isCompany = get_jwt_identity()['isCompany']

  if checkAuthorization(empTitle, empLevel, empCompID, empID, isCompany):
    company = db.session.query(Company).filter(Company.compID == compID).first()

    company.compName = compName
    company.compLogo = compLogo
    company.compPhone = compPhone
    company.compInfo = compInfo
    company.compColor = compColor

    if compPassword and compNewPassword:
      if bcrypt.check_password_hash(company.compPassword, compPassword):
        company.compPassword = bcrypt.generate_password_hash(compNewPassword).decode('utf-8')
      else:
        return jsonify({'message': 'Incorrect Password', 'success': False}), 401

    db.session.commit()

    result = company_schema.dump(company)
    return jsonify({
        'success': True,
        'data': {
          'company': result
        }
      }), 204

"""
****************************************************************************************************

                                        EMPLOYEE ROUTES

****************************************************************************************************

@desc: Add Employee
@params: compID, empName, empPhone, empEmail, empUsername, empPassword
@route: /api/v1/employee
@type: PROTECTED
"""
@app.route('/api/v1/employee', methods=['POST'])
@jwt_required()
def create_employee():
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  # if current_user['empLevel']:
  #   currentEmpLevel = current_user['empLevel']
 
  if current_user['isCompany']:
    isCompany = current_user['isCompany']
    
  empCompID = current_user['compID']
  # Admin User ? Add User : Error
  if isCompany:
    data = request.get_json()
    compID = empCompID
    empLevel = data.get('empLevel')
    empFirstName = data.get('empFirstName')
    empLastName = data.get('empLastName')
    empDOB = data.get('empDOB')
    titleID = data.get('titleID')
    empUsername = data.get('empUsername')
    empEmail = data.get('empEmail')
    empPassword = data.get('empPassword')
    empStartDate = data.get('empStartDate')
    empEndDate = None
    empPhone = data.get('empPhone')
    empPicture = data.get('empPicture')
    empSalary = data.get('empSalary')
    empHourly = data.get('empHourly')
    empStatus = True
    empSSN = data.get('empSSN')
    title = data.get('title')
    compID, empLevel, empFirstName, empLastName, empDOB, titleID, empUsername, empEmail, empPassword, empStartDate, empEndDate, empPhone, empPicture, empSalary, empHourly, empStatus, empSSN



    duplicateCheck(Employee, Employee.empUsername, empUsername)
    duplicateCheck(Employee, Employee.empEmail, empEmail)
    
    encrypted_password = bcrypt.generate_password_hash(empPassword).decode('utf-8')
    empPassword = encrypted_password

    encrypted_ssn = bcrypt.generate_password_hash(empSSN).decode('utf-8')
    empSSN = encrypted_ssn
    new_employee = Employee(compID, empLevel, empFirstName, empLastName, empDOB, titleID, empUsername, empEmail, empPassword, empStartDate, empEndDate, empPhone, empPicture, empSalary, empHourly, empStatus, empSSN)
    db.session.add(new_employee)
    db.session.commit()
    employee_result = employee_schema.dump(new_employee)

    # employee = Employee.query.filter_by(empID=employee_result['empID']).first()

    # new_title = Title(empCompID, employee.empID, titleID, title)
    # db.session.add(new_title)
    # db.session.commit()
    # title_result = title_schema.dump(new_title)

    return jsonify({
        'success': True,
        'data': {
          'employee': employee_result
          # 'title': title_result
        }
      }), 201


"""
@desc: Get Employees from Company
@params: compID
@route: /api/v1/employee
@type: PROTECTED
"""
@app.route('/api/v1/employees', methods=['GET'])
@jwt_required()
def get_employees():
  requestContentTypeCheck()

  # Get Current Users Information
  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  compID = get_jwt_identity()['compID']

  if isCompany:
    employees = db.session.query(Employee).filter(Employee.compID == compID).all()
    result = employees_schema.dump(employees)
    return jsonify({
        'success': True,
        'data': {
          'employees': result
        }
      }), 200

"""
@desc: Get Employee
@params: empID
@route: /api/v1/employee/<empID>
@type: PROTECTED
"""
@app.route('/api/v1/employee/<empID>', methods=['GET'])
@jwt_required()
def get_employee(empID):
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  compID = get_jwt_identity()['compID']

  if isCompany:
    employee = db.session.query(Employee).filter(Employee.empID == empID).first()
    result = employee_schema.dump(employee)
    return jsonify({
        'success': True,
        'data': {
          'employee': result
        }
      }), 200
  else:
    return jsonify({
      'success': False,
      'data': {}
    }), 401

"""
@desc: Update Employee Information
@params: empID, empFirstName, empLastName, empDOB, titleID, empUsername, empEmail, empPassword, empStartDate, empEndDate, empPhone, empPicture, empSalary, empHourly, empLevel
@route: /api/v1/employee/empID
@type: PROTECTED
"""
@app.route('/api/v1/employee/<int:empID>', methods=['PUT'])
@jwt_required()
def update_employee(empID):
  requestContentTypeCheck()

  # Get Current User Token Information
  current_user = get_jwt_identity()
  empCompID = current_user['compID']
  currentEmpID = current_user['empID']
  isCompany = current_user['isCompany']

  #Get Request Data
  data = request.get_json()
  empFirstName = data.get('empFirstName')
  empLastName = data.get('empLastName')
  empDOB = data.get('empDOB')
  titleID = data.get('titleID')
  empUsername = data.get('empUsername')
  empEmail = data.get('empEmail')
  empPassword = data.get('empPassword')
  empStartDate = data.get('empStartDate')
  empEndDate = data.get('empEndDate')
  empPhone = data.get('empPhone')
  empPicture = data.get('empPicture')
  empSalary = data.get('empSalary')
  empHourly = data.get('empHourly')
  empLevel = data.get('empLevel')
  empCurrentPassword = data.get('empCurrentPassword')
  empNewPassword = data.get('empNewPassword')


  # Check if Current User is Editing Themselves
  employee = Employee.query.filter_by(empID=empID).first()
  if currentEmpID == employee.empID:
    employee.empUsername = empUsername
    employee.empEmail = empEmail
    employee.empPhone = empPhone

    if empNewPassword and empCurrentPassword:
      if bcrypt.check_password_hash(employee.empPassword, empCurrentPassword):
        encrypted_password = bcrypt.generate_password_hash(empNewPassword).decode('utf-8')
        employee.empPassword = encrypted_password
      else:
        return jsonify({
          'success': False,
          'message': 'Incorrect Login Information',
          'data': {}
        }), 400

    if empPicture:
      employee.empPicture = empPicture

    db.session.commit()

    result = employee_schema.dump(employee)
    return jsonify({
        'success': True,
        'data': {
          'employee': result
        }
      }), 204

  # Check if Company or Admin is Editing an Employee
  if isCompany:
    employee = Employee.query.filter_by(empID=empID).first()

    employee.empFirstName = empFirstName if empFirstName else employee.empFirstName
    employee.empLastName = empLastName if empLastName else employee.empLastName
    employee.empDOB = empDOB if empDOB else employee.empDOB
    employee.titleID = titleID if titleID else employee.titleID
    employee.empUsername = empUsername if empUsername else employee.empUsername
    employee.empEmail = empEmail if empEmail else employee.empEmail
    employee.empStartDate = empStartDate if empStartDate else employee.empStartDate
    employee.empEndDate = empEndDate if empEndDate else employee.empEndDate
    employee.empPhone = empPhone if empPhone else employee.empPhone
    employee.empSalary = empSalary if empSalary else employee.empSalary
    employee.empHourly = empHourly if empHourly else employee.empHourly
    employee.empLevel = empLevel if empLevel else employee.empLevel

    if empNewPassword:
      encrypted_password = bcrypt.generate_password_hash(empNewPassword).decode('utf-8')
      employee.empPassword = encrypted_password
    else:
      employee.empPassword = employee.empPassword

    if empPicture:
      employee.empPicture = empPicture
    else:
      employee.empPicture = employee.empPicture
      
    db.session.commit()

    result = employee_schema.dump(employee)
    return jsonify({
        'success': True,
        'data': {
          'employee': result
        }
      }), 204

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401

"""
@desc: Delete Employee
@params: empID
@route: /api/v1/employee/empID
@type: PROTECTED
"""
@app.route('/api/v1/employee/<int:empID>', methods=['DELETE'])
@jwt_required()
def delete_employee(empID):
  requestContentTypeCheck()

  # Get Current User Token Information
  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']

  # Check if Company or Admin is Deleting an Employee
  if isCompany:
    employee = Employee.query.filter_by(empID=empID).first()
    db.session.delete(employee)
    db.session.commit()

    return jsonify({
        'success': True,
        'data': {
          'employee': empID
        }
      }), 204

  else:
    return jsonify({
        'success': False,
        'message': 'Unauthorized',
        'data': {}
      }), 401


"""
****************************************************************************************************

                                            AUTH ROUTES

****************************************************************************************************

@desc: Login Company
@params: compUsername, compPassword
@route: /api/v1/auth/company/login
@type: PUBLIC
"""
@app.route('/api/v1/auth/company/login', methods=['POST'])
def login_company():
  requestContentTypeCheck()

  data = request.get_json()
  compUsername = data.get('compUsername')
  compPassword = data.get('compPassword')

  company = db.session.query(Company).filter(Company.compUsername == compUsername).first()

  if company is None:
    return jsonify({'message': 'Incorrect Username', 'success': False}), 403

  compare_password = bcrypt.check_password_hash(company.compPassword, compPassword)

  if compare_password is False:
    return jsonify({'message': 'Incorrect Password', 'success': False}), 403

  access_token = create_access_token(identity=company_schema.dump(company))
  return jsonify({
    'success': True,
    'data' :{
      'token': access_token
    }
    }), 200


"""
@desc: Logout Company
@params: None
@route: /api/v1/auth/company/logout
@type: PROTECTED
"""
@app.route('/api/v1/auth/company/logout', methods=['POST'])
@jwt_required()
def logout_company():
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']

  if isCompany:
    return jsonify({
      'success': True,
      'message': 'Company Logged Out',
      'data': {
        'token': None
      }
    }), 200

  else:
    return jsonify({
      'success': True,
      'message': 'Employee Logged Out',
      'data': {
        'token': None
      }
    }), 200


"""
@desc: Login Employee
@params: empUsername, empPassword
@route: /api/v1/auth/employee/login
@type: PUBLIC
"""
@app.route('/api/v1/auth/employee/login', methods=['POST'])
def login_employee():
  requestContentTypeCheck()
  
  data = request.get_json()
  empUsername = data.get('empUsername')
  empPassword = data.get('empPassword')

  employee = db.session.query(Employee).filter(Employee.empUsername == empUsername).first()

  if employee is None:
    return jsonify({'message': 'Incorrect Username', 'success': False}), 403

  compare_password = bcrypt.check_password_hash(employee.empPassword, empPassword)

  if compare_password is False:
    return jsonify({'message': 'Incorrect Password', 'success': False}), 403

  access_token = create_access_token(identity=employee_schema.dump(employee))
  return jsonify({
    'success': True,
    'data' :{
      'token': access_token
    }
    }), 200


"""
@desc: Logout Employee
@params: empUsername
@route: /api/v1/auth/employee/logout
@type: PROTECTED
"""
@app.route('/api/v1/auth/employee/logout', methods=['POST'])
@jwt_required()
def logout_employee():
  requestContentTypeCheck()

  empUsername = get_jwt_identity()['empUsername']
  employee = db.session.query(Employee).filter(Employee.empUsername == empUsername).first()
  
  if not employee:
    return jsonify({'message': 'Invalid', 'success': False}), 401
  
  return jsonify({
    'message': 'Log Out Successful',
    'success': True,
    'data': {
      'token': None
    }
    }), 200


"""
****************************************************************************************************

                                            PRODUCT ROUTES

****************************************************************************************************

@desc: Get All Products for Company
@params: None
@route: /api/v1/products
@type: PROTECTED
"""
@app.route('/api/v1/products', methods=['GET'])
@jwt_required()
def get_products():
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  empCompID = current_user['compID']

  products = db.session.query(Product).filter(Product.compID == empCompID).all()
  result = products_schema.dump(products)
  return jsonify({
    'success': True,
    'data': {
      'products': result
    }
  }), 200

"""
@desc: Get Product by ID
@params: prodID
@route: /api/v1/products/<int:prodID>
@type: PROTECTED
"""
@app.route('/api/v1/products/<int:prodID>', methods=['GET'])
@jwt_required()
def get_product(prodID):
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  empCompID = current_user['compID']

  product = db.session.query(Product).filter(Product.productID == prodID, Product.compID == empCompID).first()

  if not product:
    return jsonify({
      'success': False,
      'message': 'Product Not Found',
      'data': {}
    }), 404

  result = product_schema.dump(product)
  return jsonify({
    'success': True,
    'data': {
      'product': result
    }
  }), 200

"""
@desc: Create Product
@params: prodName, prodDescription, prodPrice, prodQuantity
@route: /api/v1/products
@type: PROTECTED
"""
@app.route('/api/v1/product', methods=['POST'])
@jwt_required()
def create_product():
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  empCompID = current_user['compID']

  if isCompany:
    data = request.get_json()
    prodName = data.get('prodName')
    prodDescription = data.get('prodDescription')
    prodPrice = data.get('prodPrice')
    prodQuantity = data.get('prodQuantity')
    prodCategory = data.get('prodCategory')
    prodImage = data.get('prodImage')
    prodDate = datetime.now()

    product = Product(empCompID, prodName, prodDescription, prodPrice, prodQuantity, prodCategory, prodDate, prodImage)
    db.session.add(product)
    db.session.commit()

    return jsonify({
      'success': True,
      'message': 'Product Created',
      'data': {
        'product': product_schema.dump(product)
      }
    }), 201

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
      'data': {
        'product': {}
      }
    }), 401


"""
@desc: Update Product
@params: prodID, prodName, prodDescription, prodPrice, prodQuantity
@route: /api/v1/products/<int:prodID>
@type: PROTECTED
"""
@app.route('/api/v1/products/<int:prodID>', methods=['PUT'])
@jwt_required()
def update_product(prodID):
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  empCompID = current_user['compID']

  if isCompany:
    data = request.get_json()
    prodName = data.get('prodName')
    prodDescription = data.get('prodDescription')
    prodPrice = data.get('prodPrice')
    prodQuantity = data.get('prodQuantity')

    product = db.session.query(Product).filter(Product.prodID == prodID, Product.compID == empCompID).first()

    if not product:
      return jsonify({
        'success': False,
        'message': 'Product Not Found',
        'data': {}
      }), 404

    product.prodName = prodName
    product.prodDescription = prodDescription
    product.prodPrice = prodPrice
    product.prodQuantity = prodQuantity

    db.session.commit()

    return jsonify({
      'success': True,
      'message': 'Product Updated',
      'data': {
        'product': product_schema.dump(product)
      }
    }), 200

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401

"""
@desc: Delete Product
@params: prodID
@route: /api/v1/products/<int:prodID>
@type: PROTECTED
"""
@app.route('/api/v1/products/<int:prodID>', methods=['DELETE'])
@jwt_required()
def delete_product(prodID):
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  empCompID = current_user['compID']

  if isCompany:
    product = db.session.query(Product).filter(Product.productID == prodID, Product.compID == empCompID).first()

    if not product:
      return jsonify({
        'success': False,
        'message': 'Product Not Found',
      }), 404

    db.session.delete(product)
    db.session.commit()

    return jsonify({
      'success': True,
      'message': 'Product Deleted',
      'data': {}
    }), 200

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401

"""
****************************************************************************************************

                                            TITLE ROUTES

****************************************************************************************************

@desc: Create Title
@route: /api/v1/titles
@type: PROTECTED
"""
@app.route('/api/v1/title', methods=['POST'])
@jwt_required()
def create_title():
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  empCompID = current_user['compID']

  if isCompany:
    data = request.get_json()
    title = data.get('title')
    empID = data.get('empID')

    title = Title(empCompID, empID, title)
    db.session.add(title)
    db.session.commit()

    return jsonify({
      'success': True,
      'message': 'Title Created',
      'data': {
        'title': title_schema.dump(title)
      }
    }), 201

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
      'data': {
        'title': {}
      }
    }), 401

"""
@desc: Get All Titles
@route: /api/v1/title
@type: PROTECTED
"""
@app.route('/api/v1/title', methods=['GET'])
@jwt_required()
def get_titles():
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  empCompID = current_user['compID']

  if isCompany:
    titles = db.session.query(Title).filter(Title.compID == empCompID).all()

    if not titles:
      return jsonify({
        'success': False,
        'message': 'No Titles Found',
        'data': {}
      }), 404

    result = titles_schema.dump(titles)
    return jsonify({
      'success': True,
      'data': {
        'titles': result
      }
    }), 200

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401

"""
@desc: Update Title
@route: /api/v1/titles/<int:titleID>
@type: PROTECTED
"""
@app.route('/api/v1/titles/<int:titleID>', methods=['PUT'])
@jwt_required()
def update_title(titleID):
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  empCompID = current_user['compID']

  if isCompany:
    data = request.get_json()
    title = data.get('title')

    title = db.session.query(Title).filter(Title.titleID == titleID, Title.compID == empCompID).first()

    if not title:
      return jsonify({
        'success': False,
        'message': 'Title Not Found',
        'data': {}
      }), 404

    title.title = title

    db.session.commit()

    return jsonify({
      'success': True,
      'message': 'Title Updated',
      'data': {
        'title': title_schema.dump(title)
      }
    }), 200

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401

"""
@desc: Delete Title
@route: /api/v1/titles/<int:titleID>
@type: PROTECTED
"""
@app.route('/api/v1/title/<int:titleID>', methods=['DELETE'])
@jwt_required()
def delete_title(titleID):
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  empCompID = current_user['compID']

  if isCompany:
    title = db.session.query(Title).filter(Title.titleID == titleID, Title.compID == empCompID).first()

    if not title:
      return jsonify({
        'success': False,
        'message': 'Title Not Found',
      }), 404

    db.session.delete(title)
    db.session.commit()

    return jsonify({
      'success': True,
      'message': 'Title Deleted',
      'data': {}
    }), 200

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401


"""
****************************************************************************************************

                                            ORDER ROUTES

****************************************************************************************************

@desc: Create Order
@route: /api/v1/order
@type: PROTECTED
"""
@app.route('/api/v1/order', methods=['POST'])
@jwt_required()
def create_order():
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  empID = current_user['empID']
  empCompID = current_user['compID']

  if empID:
    data = request.get_json()
    orderItems = data.get('orderItems')
    orderTotal = data.get('orderTotal')
    orderDate = datetime.now()

    new_order = Order(empCompID, empID, orderItems, orderTotal, orderDate)
    db.session.add(new_order)
    db.session.commit()

    return jsonify({
      'success': True,
      'message': 'Order Created',
      'data': {
        'order': order_schema.dump(new_order)
      }
    }), 201

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401

"""
@desc: Delete Order
@route: /api/v1/order/<int:orderID>
@type: PROTECTED
"""
@app.route('/api/v1/order/<int:orderID>', methods=['DELETE'])
@jwt_required()
def delete_order(orderID):
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  empID = current_user['empID']
  empCompID = current_user['compID']

  if empID:
    order = db.session.query(Order).filter(Order.orderID == orderID, Order.compID == empCompID).first()

    if not order:
      return jsonify({
        'success': False,
        'message': 'Order Not Found',
      }), 404

    db.session.delete(order)
    db.session.commit()

    return jsonify({
      'success': True,
      'message': 'Order Deleted',
      'data': {}
    }), 200

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401

"""
@desc: Get Company Orders
@route: /api/v1/order
@type: PROTECTED
"""
@app.route('/api/v1/order', methods=['GET'])
@jwt_required()
def get_company_orders():
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  isCompany = current_user['isCompany']
  empCompID = current_user['compID']

  if isCompany:
    orders = db.session.query(Order).filter(Order.compID == empCompID).all()

    if not orders:
      return jsonify({
        'success': False,
        'message': 'No Orders Found',
        'data': {}
      }), 404

    result = orders_schema.dump(orders)
    return jsonify({
      'success': True,
      'data': {
        'orders': result
      }
    }), 200

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401

"""
@desc: Get Employee Orders
@route: /api/v1/order/employee
@type: PROTECTED
"""
@app.route('/api/v1/order/employee', methods=['GET'])
@jwt_required()
def get_employee_orders():
  requestContentTypeCheck()

  current_user = get_jwt_identity()
  empID = current_user['empID']
  empCompID = current_user['compID']

  if empID:
    orders = db.session.query(Order).filter(Order.compID == empCompID, Order.empID == empID).all()

    if not orders:
      return jsonify({
        'success': False,
        'message': 'No Orders Found',
        'data': {}
      }), 404

    result = orders_schema.dump(orders)
    return jsonify({
      'success': True,
      'data': {
        'orders': result
      }
    }), 200

  else:
    return jsonify({
      'success': False,
      'message': 'Unauthorized',
    }), 401


if __name__ == '__main__':
  app.run(debug=True)