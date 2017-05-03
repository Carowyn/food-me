$(document).ready(function() {
    // register our function as the "callback" to be triggered by the form's submission event
    $("#add-it").submit(searchPlace); // in other words, when the form is submitted, searchPlace() will be executed
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
        api_key: "AIzaSyB_nRsNf6hRUlEeb0nddHzuQsXPntFaPEU",
        query : restaurant + city + state + zip
    }

    // make an ajax request for places
    $.ajax({
        url: "https://maps.googleapis.com/maps/api/place/textsearch/output",
        data: params, // attach the extra paramaters onto the request
        dataType: 'jsonp',

        success: function(response) {
            // if the response comes back successfully, the code in here will execute.

            console.log("We received a response!");
            console.log(response);
        }

    })}
