from flask import abort, make_response

# Data to serve with our API
dominios = {
    'fi.uba.ar': {
        'domain': 'fi.uba.ar',
        'ip': '157.92.49.38',
        'custom': False
    },
}

# Create a handler for our read (GET) people
def obtener():
    """
    Esta funcion maneja el request GET /api/alumnos

    :return:        200 lista ordenada alfabeticamente de alumnos de la materia
    """
    # Create the list of people from our data
    return sorted(dominios.values(), key=lambda dominio: dominio.get('nombre'))

def obtener_uno(domain):
    """
    Esta funcion maneja el request GET /api/alumnos/{id_alumno}

     :id_alumno body:  id del alumno que se quiere obtener
    :return:        200 alumno, 404 alumno no encontrado
    """
    if domain not in dominios:
        return abort(404, 'El Dominio solicitado no se encuentra en sistema')

    return dominios.get(domain)

def crear(**kwargs):
    """
    Esta funcion maneja el request POST /api/alumnos

     :param body:  alumno a crear en la lista de alumnos
    :return:        201 alumno creado, 400 dni o padron duplicado
    """
    alumno = kwargs.get('body')
    dni = alumno.get('dni')
    padron = alumno.get('padron')
    nombre = alumno.get('nombre')
    if not dni or not padron or not nombre:
        return abort(400, 'Faltan datos para crear un alumno')

    dup = False
    for alumno_existente in alumnos.values():
        dup = dni == alumno_existente.get('dni') or padron == alumno_existente.get('padron')
        if dup: break

    if dup:
        return abort(400, 'DNI o Padron ya existentes')

    new_id = max(alumnos.keys()) + 1
    alumno['id'] = new_id
    alumnos[new_id] = alumno

    return make_response(alumno, 201)

def borrar(id_alumno):
    """
    Esta funcion maneja el request DELETE /api/alumnos/{id_alumno}

    :id_alumno body:  id del alumno que se quiere borrar
    :return:        200 alumno, 404 alumno no encontrado
    """
    if id_alumno not in alumnos:
        return abort(404, 'El alumno no fue encontrado')

    del alumnos[id_alumno]

    return make_response('', 204)

def modificar(**kwargs):
    dominio = kwargs.get('body')
    domain = dominio.get('domain')
    ip = dominio.get('ip')

    return make_response('',200)
