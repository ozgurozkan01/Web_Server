//
// Created by ozgur on 9/2/2024.
//

#ifndef WEB_SERVER_SERVER_INFO_H
#define WEB_SERVER_SERVER_INFO_H

#include <string>
#include <cstdint>

enum message_type
{
    http_header,
    bad_request,
    not_found
};

std::string server_messages[] =
        {
                "HTTP/1.1 200 Ok\r\n ",
                "HTTP/1.0 400 Bad Request\r\nMIME-Type: text/html\r\n\r\n<!doctype html><html><body>System is busy right now.</body></html>",
                "HTTP/1.0 404 File not found\r\nMIME-Type: text/html\r\n\r\n<!doctype html><html><body>The reuested file does not exist on this server</body></html>"
        };

std::string allowed_file_extensions[] =
        {
                "aac", "avi", "bmp", "css", "gif", "ico", "js",
                "json", "mp3", "mp4", "otf", "png", "php", "rtf",
                "svg",  "txt", "webm","webp", "woff",  "woff", "zip",
                "html", "htm",  "jpeg", "jpg",
        };

std::string mime_types[] ={
        "MIME-Type: audio/aac\r\n\r\n",
        "MIME-Type: video/x-msvideo\r\n\r\n",
        "MIME-Type: image/bmp\r\n\r\n",
        "MIME-Type: text/css\r\n\r\n",
        "MIME-Type: image/gif\r\n\r\n",
        "MIME-Type: image/vnd.microsoft.icon\r\n\r\n",
        "MIME-Type: text/javascript\r\n\r\n",
        "MIME-Type: application/json\r\n\r\n",
        "MIME-Type: audio/mpeg\r\n\r\n",
        "MIME-Type: video/mp4\r\n\r\n",
        "MIME-Type: font/otf\r\n\r\n",
        "MIME-Type: image/png\r\n\r\n",
        "MIME-Type: application/x-httpd-php\r\n\r\n",
        "MIME-Type: application/rtf\r\n\r\n",
        "MIME-Type: image/svg+xml\r\n\r\n",
        "MIME-Type: text/plain\r\n\r\n",
        "MIME-Type: video/webm\r\n\r\n",
        "MIME-Type: video/webp\r\n\r\n",
        "MIME-Type: font/woff\r\n\r\n",
        "MIME-Type: font/woff2\r\n\r\n",
        "MIME-Type: application/zip\r\n\r\n",
        "MIME-Type: text/html\r\n\r\n",
        "MIME-Type: text/html\r\n\r\n",
        "MIME-Type: image/jpeg\r\n\r\n",
        "MIME-Type: image/jpeg\r\n\r\n",
};

#endif //WEB_SERVER_SERVER_INFO_H
