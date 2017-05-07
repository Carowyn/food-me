$(document).ready(function() {
    // register our function as the "callback" to be triggered by the form's submission event
    $("#add-it").click(searchPlace); // in other words, when the form is submitted, searchPlace() will be executed
});

function searchPlace(event) {
    // This prevents the form submission from doing what it normally does: send a request (which would cause our page to refresh).
    // Because we will be making our own AJAX request, we dont need to send a normal request and we definitely don't want the page to refresh.
    event.preventDefault();

    // get the user's input text from the DOM
        var restaurant = $("#new-food").val();
        var city = $("#city").val();
        var state = $("#state").val();
        var zip = $("#zip").val();

    // configure a few parameters to attach to our request
    var params = {
        query : restaurant + city + state + zip,
        key: "AIzaSyB_nRsNf6hRUlEeb0nddHzuQsXPntFaPEU"  // switched query and key positions
    }

    // make an ajax request for places
    $.ajax({
        url: "https://maps.googleapis.com/maps/api/place/textsearch/output",
        data: params, // attach the extra paramaters onto the request
        dataType: "jasonp",  // hopefully stop the 404 error

        success: function(response) {
            // if the response comes back successfully, the code in here will execute.

            console.log("We received a response!");
            console.log(response);
        },

        error: function() {
            console.log("I'm sorry, it didn't work this time!");
        }

    })}
