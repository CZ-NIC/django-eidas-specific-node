function formAutoSubmit () {
    var form = (
        document.getElementById('proxy-service-request-form')
        || document.getElementById('identity-provider-response-form'))
    if (!form) {
        return
    }

    form.submit()
    var submit = form.querySelector('input[type="submit"]')
    if (submit) {
        submit.className += ' disabled'
        submit.setAttribute('disabled', 'disabled')
        setTimeout(function () {
            submit.className = submit.className.replace(/(?:^|\s)disabled(?!\S)/, '')
            submit.removeAttribute('disabled')
        }, 3000)
    }
}

document.addEventListener('DOMContentLoaded', formAutoSubmit)
