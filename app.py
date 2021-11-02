from flask import Flask, request, session, url_for
from flask.templating import render_template
from werkzeug.utils import redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os


#Conexion a la base de datos
dirdb= "sqlite:///" + os.path.abspath(os.getcwd()) + "/BD_UTadeo.sqlite"




app = Flask(__name__)
#Creacion de llave secreta para la sesion
app.secret_key= b'_QjdSQsd+*567-6_//Sf'

app.config['SQLALCHEMY_DATABASE_URI'] = dirdb
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db=SQLAlchemy(app)


class tb_usuarios(db.Model):
    __tablename__ = 'tb_usuarios'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre_usuario = db.Column(db.String(100),nullable=False, unique=True)
    password = db.Column(db.String(200))
    rol = db.Column(db.String(30))

class tb_cursos(db.Model):
    __tablename__ = 'tb_cursos'
    id_curso = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    num_alumnos = db.Column(db.Integer)
    num_asignaturas = db.Column(db.Integer, nullable=False, unique=True)
    fecha_inicio = db.Column(db.Date) 
    fecha_fin = db.Column(db.Date)
    semestre = db.Column(db.Integer)

class tb_estudiantes(db.Model):
    __tablename__ = 'tb_estudiantes'
    id_estudiante = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    apellido = db.Column(db.String(100))
    correo = db.Column(db.String(100), nullable=False, unique=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey(tb_usuarios.id_usuario, ondelete="CASCADE", onupdate="CASCADE"))
    users = db.relationship("tb_usuarios", backref="tb_estudiantes")
    id_curso = db.Column(db.String(100), db.ForeignKey(tb_cursos.id_curso, ondelete="CASCADE", onupdate="CASCADE"))



class tb_admin(db.Model):
    __tablename__ = 'tb_admin'
    id_admin = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    apellido = db.Column(db.String(100))
    correo = db.Column(db.String(100), nullable=False, unique=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey(tb_usuarios.id_usuario, ondelete="CASCADE", onupdate="CASCADE"))

    
    
class tb_asignaturas(db.Model):
    __tablename__ = 'tb_asignaturas'
    id_asignatura = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    num_creditos = db.Column(db.Integer)
    id_curso = db.Column(db.Integer, db.ForeignKey(tb_cursos.id_curso, ondelete="CASCADE", onupdate="CASCADE"))

class tb_docentes(db.Model):
    __tablename__ = 'tb_docentes'
    id_docente = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    apellido = db.Column(db.String(100))
    correo = db.Column(db.String(100), nullable=False, unique=True)
    id_usuario = db.Column(db.Integer, db.ForeignKey(tb_usuarios.id_usuario, ondelete="CASCADE", onupdate="CASCADE"))
    id_asignatura = db.Column(db.String(100), db.ForeignKey(tb_asignaturas.id_asignatura, ondelete="CASCADE", onupdate="CASCADE"))

class tb_actividades(db.Model):
    __tablename__ = 'tb_actividades'
    id_actividad = db.Column(db.Integer, primary_key=True)
    descripcion = db.Column(db.String(100))
    porcentaje = db.Column(db.FLOAT)
    Calificacion = db.Column(db.FLOAT)
    estado = db.Column(db.String(30))
    id_asignatura = db.Column(db.Integer, db.ForeignKey(tb_asignaturas.id_asignatura, ondelete="CASCADE", onupdate="CASCADE"))



db.create_all()##para crear tablas de la base de datos

#RUTA INDEX
@app.route("/")
def index():
    return redirect(url_for('login'))
    #return render_template('index.html')

#RUTA LOGIN 

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
    return redirect(url_for('login'))

#RUTAS ADMINISTRADOR

#ADMIN USUARIOS

@app.route('/admin')
def admin():
    if 'username' in session and tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().rol == "admin":
        id_u=tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().id_usuario
        datos= tb_admin.query.filter_by(id_admin=id_u).first()
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
            if request.form['rol'] == 'estudiante':
                new_user2=tb_estudiantes(nombre=request.form['name_usuario'], apellido=request.form['lastname_usuario'], id_estudiante=id_u, correo=request.form['mail_usuario'])
            elif request.form['rol'] == 'docente':
                new_user2=tb_docentes(nombre=request.form['name_usuario'], apellido=request.form['lastname_usuario'], id_docente=id_u, correo=request.form['mail_usuario'])    
            elif request.form['rol'] == 'admin':
                new_user2=tb_admin(nombre=request.form['name_usuario'], apellido=request.form['lastname_usuario'], id_admin=id_u, correo=request.form['mail_usuario'])    
            db.session.add(new_user)
            db.session.commit()
            db.session.add(new_user2)
            db.session.commit()
            return redirect(url_for('usuarios'))
        
        return render_template('administrador_crearUsuario.html')
    return 'No se encuentra logueado '

@app.route('/admin/editarUsuarios', methods=['POST', 'GET'])
def editarUsuarios():
    u=request.args.get('u')
    user=tb_usuarios.query.filter_by(nombre_usuario=u).first()
    
    if 'username' in session and tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().rol == "admin":

        if request.method == 'POST':
            user=tb_usuarios.query.filter_by(id_usuario=request.form['id']).first()
            if user.rol == 'estudiante':
                usuario=tb_estudiantes.query.filter_by(id_estudiante=user.id_usuario).first()
                usuario.nombre=request.form['name_usuario']
                usuario.apellido=request.form['lastname_usuario']
                usuario.correo=request.form['mail_usuario']
                usuario.id_estudiante=request.form['doc']
                user.id_usuario=request.form['doc']
                db.session.commit()
                return redirect(url_for('usuarios'))
            if user.rol == 'docente':
                usuario=tb_docentes.query.filter_by(id_docente=user.id_usuario).first()
                usuario.nombre=request.form['name_usuario']
                usuario.apellido=request.form['lastname_usuario']
                usuario.correo=request.form['mail_usuario']
                usuario.id_docente=request.form['doc']
                user.id_usuario=request.form['doc']
                db.session.commit()
                return redirect(url_for('usuarios'))
            if user.rol == 'admin':
                usuario=tb_admin.query.filter_by(id_admin=user.id_usuario).first()
                usuario.nombre=request.form['name_usuario']
                usuario.apellido=request.form['lastname_usuario']
                usuario.correo=request.form['mail_usuario']
                usuario.id_admin=request.form['doc']
                user.id_usuario=request.form['doc']
                db.session.commit()
                return redirect(url_for('usuarios'))        
        ##Prerender
        if user.rol=="admin":
            usuario=tb_admin.query.filter_by(id_admin = user.id_usuario).first()
            return render_template('administrador_editarUsuario.html',usuario=usuario, user=user)
        if user.rol=="estudiante":
            usuario=tb_estudiantes.query.filter_by(id_estudiante=user.id_usuario).first()
            return render_template('administrador_editarUsuario.html',usuario=usuario, user=user)
        if user.rol=="docente":
            usuario=tb_docentes.query.filter_by(id_docente=user.id_usuario).first()
            return render_template('administrador_editarUsuario.html',usuario=usuario, user=user)
        
          
    return 'No se encuentra logueado'  

#Boton eliminar usuario no funciona
@app.route('/admin/eliminarUsuarios/', methods=['POST', 'GET'])
def elimUsuarios():
    if 'username' in session and tb_usuarios.query.filter_by(nombre_usuario=session['username']).first().rol == "admin":
        
        variable1=tb_usuarios.query.get(request.args.get('id'))
        db.session.delete(variable1)
        db.session.commit()
        variable2=tb_docentes.query.get(request.args.get('id'))
        if variable2 != None:
            db.session.delete(variable2)
            db.session.commit()
        variable3=tb_estudiantes.query.get(request.args.get('id'))
        if variable3 != None:
            db.session.delete(variable3)
            db.session.commit()
        variable4=tb_admin.query.get(request.args.get('id'))
        if variable4 != None:
            db.session.delete(variable4)
            db.session.commit()
        

         
        return redirect(url_for('usuarios',usuarios=variable1)) #redirecciona a admin/usuarios para verificar que se elimino
            
    return 'No se encuentra logueado' 
    


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
            datos= tb_docentes.query.filter_by(id_docente=id_u).first()
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

if __name__ == '__main__':
   
    app.run(debug=True)