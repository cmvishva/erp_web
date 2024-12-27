(function ($) {
    'use strict';
    document.getElementById('basic').addEventListener('click', () => {
        Toastify({
            text: "This is a toast",
            duration: 3000
        }).showToast();
    })
    document.getElementById('background').addEventListener('click', () => {
        Toastify({
            text: "This is a toast",
            duration: 3000,
            backgroundColor: "linear-gradient(45deg, #9977f9, #6935f7)",
        }).showToast();
    })
    document.getElementById('close').addEventListener('click', () => {
        Toastify({
            text: "Click close button",
            duration: 3000,
            close:true,
            backgroundColor: "#8156F8",
        }).showToast();
    })
    document.getElementById('top-left').addEventListener('click', () => {
        Toastify({
            text: "This is toast in top left",
            duration: 3000,
            close:true,
            gravity:"top",
            position: "left",
            backgroundColor: "#8156F8",
        }).showToast();
    })
    document.getElementById('top-center').addEventListener('click', () => {
        Toastify({
            text: "This is toast in top center",
            duration: 3000,
            close:true,
            gravity:"top",
            position: "center",
            backgroundColor: "#8156F8",
        }).showToast();
    })
    document.getElementById('top-right').addEventListener('click', () => {
        Toastify({
            text: "This is toast in top right",
            duration: 3000,
            close:true,
            gravity:"top",
            position: "right",
            backgroundColor: "#8156F8",
        }).showToast();
    })
    document.getElementById('bottom-right').addEventListener('click', () => {
        Toastify({
            text: "This is toast in bottom right",
            duration: 3000,
            close:true,
            gravity:"bottom",
            position: "right",
            backgroundColor: "#8156F8",
        }).showToast();
    })
    document.getElementById('bottom-center').addEventListener('click', () => {
        Toastify({
            text: "This is toast in bottom center",
            duration: 3000,
            close:true,
            gravity:"bottom",
            position: "center",
            backgroundColor: "#8156F8",
        }).showToast();
    })
    document.getElementById('bottom-left').addEventListener('click', () => {
        Toastify({
            text: "This is toast in bottom left",
            duration: 3000,
            close:true,
            gravity:"bottom",
            position: "left",
            backgroundColor: "#8156F8",
        }).showToast();
    })
}(jQuery));