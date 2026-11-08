from django.http import HttpResponse, JsonResponse
from django.views.defaults import page_not_found
from django.urls import include, path

from django.conf import settings


def ui_missing(request):
    return HttpResponse(
        "<h1>AetherEDR</h1><p>UI bundle not built. Run <code>cd frontend &amp;&amp; npm install "
        "&amp;&amp; npm run build</code>. The API is live at <code>/api/</code>.</p>"
        if not (settings.UI_DIST / "index.html").exists()
        else "<h1>AetherEDR</h1>"
    )


def not_found(request, exception=None):
    if request.path.startswith("/api/"):
        return JsonResponse({"detail": "Not found."}, status=404)
    return page_not_found(request, exception)


handler404 = "aether.urls.not_found"

urlpatterns = [
    path("api/", include("edr.urls")),
    path("", ui_missing),  # WhiteNoise serves index.html first when the UI exists
]
