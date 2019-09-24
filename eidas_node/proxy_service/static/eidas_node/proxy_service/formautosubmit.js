function formAutoSubmit () {
    var form = document.querySelector('form.auto-submit')
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
