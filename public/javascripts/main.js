$(function() {
  initFormsValidation();
  initHideFlash();
  initRemoveErrorLabelOnType();
});

/*


 */


 $.validator.addMethod("postcodeNL", function(value, element, val) {
    var rege = /^[1-9][0-9]{3} ?(?!sa|sd|ss)[a-z]{2}$/i;

     return rege.test(value);
 }, "Een postcode bestaat uit 4 cijfers en 2 letters");

function initFormsValidation () {
  $('.validate-form').each(function () {
    $(this).validate({
      rules : {
        password : {
            minlength : 5
        },
        password_confirm : {
          //  minlength : 5,
            equalTo : "#password"
        },
        postcode : {
          postcodeNL: true,
        },
        firstName: {
          required: true,
        },
        lastName: {
          required: true,
        },
      },
      messages: {
        firstName: {
          required: 'Je voornaam is nog niet ingevuld',
        },
        lastName: {
          required: 'Je achternaam is nog niet ingevuld',
        },
        postcode: {
          required: 'Een postcode bestaat uit 4 cijfers en 2 letters',
        },
      },
    });
  });
}


function initRemoveErrorLabelOnType ( ){
  $('.side-error input').on('keydown', function () {
    var $sideError = $(this).closest('.side-error')
    $sideError.find('.error-label').remove();
    $sideError.removeClass('side-error');
  })
}

function initHideFlash() {
  $('.flash-container .close-button').click(function() {
    $(this).closest('.flash-container').remove();
  });

  setTimeout(function() {
  //  $('.flash-container').remove();
  }, 5000);
}
