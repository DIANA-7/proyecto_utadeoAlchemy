const close_estudiante = document.getElementById('student');
const close_docente = document.getElementById('teacher');
const close_empleado = document.getElementById('emp');
const close_form = document.querySelector('.close');
const name_sesion = document.getElementById('name');


//Eventos para hacer formulario modal

close_estudiante.addEventListener('click', () => {
    document.getElementById('form').style.display = 'block';
});

close_docente.addEventListener('click', () => {
    document.getElementById('form').style.display = 'block';
});

close_empleado.addEventListener('click', () => {
    document.getElementById('form').style.display = 'block';
});

close_form.addEventListener('click', () => {
    document.getElementById('form').style.display = 'none';
    document.getElementById('form').reset();
})



//validar formulario Inicio de sesion

document.getElementById("form").addEventListener('submit', (evento) => {
    evento.preventDefault();
    const usuario = document.getElementById('name').value;
    if (usuario.length == 0) {
        alert('Por favor, ingresa tu nombre de usuario');
        return;
    }

    const clave = document.getElementById('password').value;
    if (clave.length < 8) {
        alert('La longitud de la clave no es la correcta');
        return;
    }
    this.submit();
});