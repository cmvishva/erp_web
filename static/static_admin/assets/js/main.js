(function ($) {
    'use strict';

    //------------------------------------------------------------------------------------------------------------------
    // code print
    //------------------------------------------------------------------------------------------------------------------
    window.prettyPrint && prettyPrint();
    $(window).on('load', function() {
        $('.chat-scroll').scrollTop(1000);
    })

    $(document).ready(function(){


        //------------------------------------------------------------------------------------------------------------------
        // Theme Color Change
        //------------------------------------------------------------------------------------------------------------------
        $('#color-1').on('click', function(){
            $('link#styles').attr('href','assets/css/style.css')
            $('img#logoBig').attr('src','assets/images/logo-big.png')
            $('img#logoSmall').attr('src','assets/images/logo-small.png')
        })
        $('#color-2').on('click', function(){
            $('link#styles').attr('href','assets/css/color-2.css')
            $('img#logoBig').attr('src','assets/images/logo-big-2.png')
            $('img#logoSmall').attr('src','assets/images/logo-small-2.png')
        })
        $('#color-3').on('click', function(){
            $('link#styles').attr('href','assets/css/color-3.css')
            $('img#logoBig').attr('src','assets/images/logo-big-3.png')
            $('img#logoSmall').attr('src','assets/images/logo-small-3.png')
        })
        $('#color-4').on('click', function(){
            $('link#styles').attr('href','assets/css/color-4.css')
            $('img#logoBig').attr('src','assets/images/logo-big-4.png')
            $('img#logoSmall').attr('src','assets/images/logo-small-4.png')
        })
        $('#color-5').on('click', function(){
            $('link#styles').attr('href','assets/css/color-5.css')
            $('img#logoBig').attr('src','assets/images/logo-big-5.png')
            $('img#logoSmall').attr('src','assets/images/logo-small-5.png')
        })
        $('#color-6').on('click', function(){
            $('link#styles').attr('href','assets/css/color-6.css')
            $('img#logoBig').attr('src','assets/images/logo-big-6.png')
            $('img#logoSmall').attr('src','assets/images/logo-small-6.png')
        })
        $('#color-7').on('click', function(){
            $('link#styles').attr('href','assets/css/color-7.css')
            $('img#logoBig').attr('src','assets/images/logo-big-7.png')
            $('img#logoSmall').attr('src','assets/images/logo-small-7.png')
        })
        $('#color-8').on('click', function(){
            $('link#styles').attr('href','assets/css/color-8.css')
            $('img#logoBig').attr('src','assets/images/logo-big-8.png')
            $('img#logoSmall').attr('src','assets/images/logo-small-8.png')
        })
        $('#color-9').on('click', function(){
            $('link#styles').attr('href','assets/css/color-9.css')
            $('img#logoBig').attr('src','assets/images/logo-big-5.png')
            $('img#logoSmall').attr('src','assets/images/logo-small-5.png')
        })


        //------------------------------------------------------------------------------------------------------------------
        // Template Nav Position Change
        //------------------------------------------------------------------------------------------------------------------
        $('#navChange').on('click', function() {
            if ($('.header').hasClass('horizontal-nav')) {
                $('body').removeClass('active')
                $('#navChange .bi').removeClass('bi-arrow-bar-left').addClass('bi-arrow-bar-up')
                $('.header').removeClass('horizontal-nav')
                $('.header .logo').removeClass('no-sidebar-logo')
                $('.fixed-sidebar').removeClass('hide')
                $('.sidebar-collapse, .sidebar-collapse-mini').fadeIn(300)
                $('.main-content').removeClass('no-sidebar')
            } else {
                $('body').addClass('active')
                $('#navChange .bi').addClass('bi-arrow-bar-left').removeClass('bi-arrow-bar-up')
                $('.header').addClass('horizontal-nav')
                $('.header .logo').addClass('no-sidebar-logo')
                $('.fixed-sidebar').addClass('hide')
                $('.sidebar-collapse, .sidebar-collapse-mini').fadeOut(300)
                $('.main-content').addClass('no-sidebar')
            }
        })
        $(".horizontal-menu li a").each(function() {
            var pageUrl = window.location.href.split(/[?#]/)[0];
              if (this.href == pageUrl) {
                  $(this).addClass("active");
            }
        })


        //------------------------------------------------------------------------------------------------------------------
        // Template Sidebar Collapse
        //------------------------------------------------------------------------------------------------------------------
        $('.sidebar-collapse, .sidebar-collapse-mini').on('click', function(e){
            e.preventDefault();
            e.stopPropagation();
            if($(window).width() > 1299) {
                $('.header .logo').toggleClass('small')
                $('.fixed-sidebar').toggleClass('collapsed')
                $('.main-content').toggleClass('expanded')
            } else {
                $('.fixed-sidebar').toggleClass('sidebar-mini')
                $('.fixed-sidebar').removeClass('collapsed')
            }
        });
        $('.fixed-sidebar').hover(function(){
            $(this).removeClass('collapsed')
            $('.header .logo').removeClass('small')
            $('.main-content').removeClass('expanded')
        })


        //------------------------------------------------------------------------------------------------------------------
        // Template Sidebar Dropdown 
        //------------------------------------------------------------------------------------------------------------------
        $('.sub-menu').hide(300);
        $('.has-sub').on('click', function() {
            $(this).toggleClass('open')
            $(this).children('.sub-menu').stop().slideToggle();
            $(this).siblings().children('.sub-menu').stop().slideUp().parent('.sidebar-item').removeClass('open');
            $(this).parent('.sub-menu').slideToggle().stop().parent('.sidebar-item').removeClass('open');
        });
        $(".fixed-sidebar li a").each(function() {
            var pageUrl = window.location.href.split(/[?#]/)[0];
              if (this.href == pageUrl) {
                  $(this).addClass("active");
                  $(this).parent().parent().prev().addClass("active show");
            }
        })
        $(".fixed-sidebar .show").siblings().slideDown().stop().parent(".has-sub").addClass("open")


        //------------------------------------------------------------------------------------------------------------------
        // Template Sidebar Profile Close
        //------------------------------------------------------------------------------------------------------------------
        $('#profileClose').on('click', function() {
            $('.sidebar-profile').hide(500)
        })

        //------------------------------------------------------------------------------------------------------------------
        // Bootstrap Tooltip
        //------------------------------------------------------------------------------------------------------------------
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
        })



        //------------------------------------------------------------------------------------------------------------------
        // Bootstrap Alert
        //------------------------------------------------------------------------------------------------------------------
        var alertPlaceholder = document.getElementById('liveAlertPlaceholder')
        var alertTrigger = document.getElementById('liveAlertBtn')

        function alert(message, type) {
            var wrapper = document.createElement('div')
            wrapper.innerHTML = '<div class="alert alert-' + type + ' alert-dismissible" role="alert">' + message + '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>'

            alertPlaceholder.append(wrapper)
        }
        if (alertTrigger) {
            alertTrigger.addEventListener('click', function () {
                alert('Nice, you triggered this alert message!', 'success')
            })
        };


        //------------------------------------------------------------------------------------------------------------------
        // Bootstrap Popover
        //------------------------------------------------------------------------------------------------------------------
        var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'))
        var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl)
        });


        //------------------------------------------------------------------------------------------------------------------
        // Sweet Alerts Plugin Initialize
        //------------------------------------------------------------------------------------------------------------------
        $('.btn-demo-sweet-alert').each(function() {
             var $btn = $(this),
                 id = $btn.attr('id');
             if (id == 'undefined') return;
             switch(id) {
                 case 'demo-sweet-alert-basic':
                     $btn.on('click', function() {
                         swal("Here's a message!");
                     });
                     break;
                 case 'demo-sweet-alert-basic-title':
                     $btn.on('click', function() {
                         swal("Here's a message!", "It's pretty, isn't it?");
                     });
                     break;
                 case 'demo-sweet-alert-success':
                     $btn.on('click', function() {
                         swal("Good job!", "You clicked the button!", "success");
                     });
                     break;
                 case 'demo-sweet-alert-confirm':
                     $btn.on('click', function() {
                         swal({
                             title: 'Are you sure?',
                             text: 'You will not be able to recover this imaginary file!',
                             type: 'warning',
                             showCancelButton: true,
                             confirmButtonColor: '#DD6B55',
                             confirmButtonText: 'Yes, delete it!',
                             cancelButtonText: 'No, cancel plx!',
                             closeOnConfirm: false,
                             closeOnCancel: false
                         }, function(isConfirm){
                             if (isConfirm) swal('Deleted!', 'Your imaginary file has been deleted.', 'success');
                             else swal('Cancelled', 'Your imaginary file is safe :)', 'error');
                         });
                     });
                     break;
                 case 'demo-sweet-alert-custom-icon':
                     $btn.on('click', function() {
                         swal({
                             title: 'Sweet!',
                             text: 'Here\'s a custom image.',
                             imageUrl: 'assets/images/sweet-alert-thumbs-up.png'
                         });
                     });
                     break;
                 case 'demo-sweet-alert-html':
                     $btn.on('click', function() {
                         swal({
                             title: 'HTML <small>Title</small>!',
                             text: 'A custom <span style="color:#F8BB86">html<span> message.',
                             html: true
                         });
                     });
                     break;
                 case 'demo-sweet-alert-auto-close':
                     $btn.on('click', function() {
                         swal({
                             title: "Auto close alert!",
                             text: "I will close in 2 seconds.",
                             timer: 2000,
                             showConfirmButton: false
                         });
                     });
                     break;
                 case 'demo-sweet-alert-prompt':
                     $btn.on('click', function() {
                         swal({
                             title: 'An input!',
                             text: 'Write something interesting:',
                             type: 'input',
                             showCancelButton: true,
                             closeOnConfirm: false,
                             animation: 'slide-from-top',
                             inputPlaceholder: 'Write something'
                         }, function(inputValue){
                             if (inputValue === false) return false;
                             if (inputValue === '') {
                                 swal.showInputError('You need to write something!');
                                 return false
                             }
                             swal('Nice!', 'You wrote: ' + inputValue, 'success');
                         });
                     });
                     break;
                 case 'demo-sweet-alert-loader':
                     $btn.on('click', function() {
                         swal({
                             title: 'Ajax request example',
                             text: 'Submit to run ajax request',
                             type: 'info',
                             showCancelButton: true,
                             closeOnConfirm: false,
                             showLoaderOnConfirm: true
                         },  function(){
                             setTimeout(function(){
                                 swal('Ajax request finished!');
                             }, 2000);
                         });
                    });
                break;
             }
        });

        
        //------------------------------------------------------------------------------------------------------------------
        // Dragula Plugin Initialize
        //------------------------------------------------------------------------------------------------------------------
        dragula([document.getElementById('left'), document.getElementById('right'), document.getElementById('center')]);


        //------------------------------------------------------------------------------------------------------------------
        // bootstrap form validation
        //------------------------------------------------------------------------------------------------------------------
        // Example starter JavaScript for disabling form submissions if there are invalid fields
        // Fetch all the forms we want to apply custom Bootstrap validation styles to
        var forms = document.querySelectorAll('.needs-validation')
        // Loop over them and prevent submission
        Array.prototype.slice.call(forms)
        .forEach(function (form) {
            form.addEventListener('submit', function (event) {
            if (!form.checkValidity()) {
                event.preventDefault()
                event.stopPropagation()
            }
    
            form.classList.add('was-validated')
            }, false)
        });

        
        //------------------------------------------------------------------------------------------------------------------
        // Input Product Picture On Add A Product Page
        //------------------------------------------------------------------------------------------------------------------
        $('#AddProduct').bs_dropzone({
            boxClass: '',
            noneColorClass: '',
            preview: true,
            dropzoneTemplate: '<div class="bs-dropzone"><div class="bs-dropzone-area text-center"><div class="icon"><i class="bi bi-cloud-upload"></i></div><p class="mb-5"><small>Image size must be 400 * 400</small></p></div><div class="bs-dropzone-message"></div><div class="bs-dropzone-preview"></div></div>',
            parentTemplate: '<div class="row g-2"></div>',
            childTemplate: '<div class="uploaded-image"></div>',
            language: {
                emptyText: 'Drop File Here or Click To Upload',
                dragText: 'Drop File Here',
                dropText: '_t_ File(s)'
            },
        });
    });
}(jQuery));