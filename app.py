from flask import Flask, request, session, url_for
from flask.templating import render_template
from werkzeug.utils import redirect
from flask_sqlalchemy import SQLAlchemy 
from werkzeug.security import generate_password_hash, check_password_hash
import os


#Conexion a la base de datos
dirdb= "sqlite:///" + os.path.abspath(os.getcwd()) + "/prueba.sqlite"




app = Flask(__name__)
#Creacion de llave secreta para la sesion
app.secret_key= b'_QjdSQsd+*567-6_//Sf'

app.config['SQLALCHEMY_DATABASE_URI'] = dirdb
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db=SQLAlchemy(app)

class tb_usuarios(db.Model):
    __tablename__ = 'tb_usuarios'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre_usuario = db.Column(db.String(100))
    password = db.Column(db.String(200))
    rol = db.Column(db.String(30))

class tb_estudiantes(db.Model):
    __tablename__ = 'tb_estudiantes'
    id_estudiante = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    apellido = db.Column(db.String(100))
    correo = db.Column(db.String(100))
    ##id_curso = db.Column(db.String(100))
    ##id_usuario = db.Column(db.Integer)



db.create_all()##para crear tablas de bases de datos

#RUTA INDEX
@app.route("/")
def index():
    return render_template('index.html')

#RUTA LOGIN /no terminado aun.

@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        user = tb_usuarios.query.filter_by(nombre_usuario=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['username'] = request.form['username']
            if user.rol == 'admin':
                return redirect(url_for('admin'))
            elif user.rol == 'estudiante':
                return redirect(url_for('estudiante'))
            elif user.rol == 'docente':
                return redirect(url_for('docente'))

            
        
        print(request.form['password'])
        return "Usuario o password incorrecto, intente de nuevo"
    return render_template('/login.html')

#Logout
@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

#RUTAS ADMINISTRADOR

#ADMIN USUARIOS

@app.route('/admin')
def admin():
    if 'username' in session and tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().rol == "admin":
        id_u=tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().id_usuario
        datos= tb_estudiantes.query.filter_by(id_estudiante=id_u).first()
        return render_template('administrador.html', datos=datos, usuario=session['username'])
        
    return 'No se encuentra logueado' 


@app.route('/admin/usuarios')
def usuarios():
    if 'username' in session and tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().rol == "admin":
        usuarios = tb_usuarios.query.all()


        return render_template('administrar_usuario.html', usuarios=usuarios)
    return 'No se encuentra logueado'    

@app.route('/admin/crearUsuarios', methods=['POST', 'GET'])
def crearUsuarios():
    if 'username' in session and tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().rol == "admin":
        if request.method == 'POST':
            hashed_pw = generate_password_hash(request.form['password'], method='sha256')
            id_u=request.form['doc']
            new_user=tb_usuarios(nombre_usuario=request.form['usuario'], password=hashed_pw, rol=request.form['rol'], id_usuario=id_u)
            new_user2=tb_estudiantes(nombre=request.form['name_usuario'], apellido=request.form['lastname_usuario'], id_estudiante=id_u, correo=request.form['mail_usuario'])
            db.session.add(new_user)
            db.session.commit()
            db.session.add(new_user2)
            db.session.commit()
            return redirect(url_for('index'))
        
        return render_template('administrador_crearUsuario.html')
    return 'No se encuentra logueado '

@app.route('/admin/editarUsuarios', methods=['POST', 'GET'])
def editarUsuarios():
    return render_template('administrador_editarUsuario.html')

@app.route('/admin/eliminarUsuarios', methods=['POST', 'GET'])
def elimUsuarios():
    return render_template('administrar_eliminarUsuario.html')

#ADMIN CURSOS
@app.route('/admin/cursos')
def cursos():
    return render_template('administrador_cursos.html')

@app.route('/admin/crearCursos', methods=['POST', 'GET'])
def crearCursos():
    return render_template('administrador_crearCurso.html')

@app.route('/admin/editarCurso', methods=['POST', 'GET'])
def editarCurso():
    return render_template('administrador_editarCurso.html')

@app.route('/admin/elimCurso', methods=['POST', 'GET'])
def elimCurso():
    return render_template('administrador_eliminarCurso.html')

#ADMIN ASIGNATURAS

@app.route('/admin/crearAsignatura', methods=['POST', 'GET'])
def crearAsignatura():
    return render_template('administrador_crearAsignatura.html')

@app.route('/admin/editarAsignatura', methods=['POST', 'GET'])
def editarAsignatura():
    return render_template('administrador_editarAsignatura.html')

@app.route('/admin/elimAsignatura', methods=['POST', 'GET'])
def elimAsignatura():
    return render_template('administrador_eliminarAsignatura.html')

#RUTAS DOCENTE

@app.route('/docente')
def docente():
    if 'username' in session and tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().rol == "docente":
            id_u=tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().id_usuario
            datos= tb_estudiantes.query.filter_by(id_estudiante=id_u).first()
            return render_template('docente.html', datos=datos, usuario=session['username'])
            
    return 'No se encuentra logueado' 


@app.route('/docente/cursos', methods=['POST', 'GET'])
def docenteCurso():
    return render_template('docente_curso.html')

@app.route('/docente/calificaciones', methods=['POST', 'GET'])
def calificaciones():
    return render_template('docente_calificaciones.html')

@app.route('/docente/actividades', methods=['POST', 'GET'])
def actividades():
    return render_template('docente_actividades.html')

#RUTAS ESTUDIANTE

@app.route('/estudiante')
def estudiante():
    if 'username' in session and tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().rol == "estudiante":
        id_u=tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().id_usuario
        datos= tb_estudiantes.query.filter_by(id_estudiante=id_u).first()
        return render_template('estudiante.html', datos=datos, usuario=session['username'])
        
    return 'No se encuentra logueado'    

@app.route('/estudiante/cursos', methods=['POST', 'GET'])
def estudianteCurso():
    return render_template('estudiante_curso.html')

@app.route('/estudiante/calificaciones', methods=['POST', 'GET'])
def estudianteCalificaciones():
    return render_template('estudiante_calificaciones.html')

@app.route('/estudiante/actividades', methods=['POST', 'GET'])
def estudianteActividades():
    return render_template('estudiante_actividades.html')