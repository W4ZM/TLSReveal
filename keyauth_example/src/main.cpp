#include <Windows.h>
#include "auth.hpp"
#include <string>
#include <thread>
#include "utils.hpp"
#include "skStr.h"
#include <iostream>

void sessionStatus();

using namespace KeyAuth;


std::string name = "Lastninjadz's Application"; // App name
std::string ownerid = "VhWPOCZhyB"; // Account ID
std::string version = "1.0"; // Application version. Used for automatic downloads see video here https://www.youtube.com/watch?v=kW195PLCBKs
std::string url = "https://keyauth.win/api/1.3/"; // change if using KeyAuth custom domains feature
std::string path = "";



api KeyAuthApp(name, ownerid, version, url, path);

int main()
{
    std::string consoleTitle = "CRACKME W4ZM";
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << "\n\n Connecting..";

    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << "\n Status: " << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    std::string key;

    std::cout << "\n Enter license: ";
    std::cin >> key;
    KeyAuthApp.license(key, "");


    if (KeyAuthApp.response.message.empty()) exit(11);
    if (!KeyAuthApp.response.success)
    {
        std::cout << "\n Status: " << KeyAuthApp.response.message;
        std::remove("test.json");
        Sleep(1500);
        exit(1);
    }


    /*
    * Do NOT remove this checkAuthenticated() function.
    * It protects you from cracking, it would be NOT be a good idea to remove it
    */
    std::thread run(checkAuthenticated, ownerid);
    // do NOT remove checkAuthenticated(), it MUST stay for security reasons
    std::thread check(sessionStatus); // do NOT remove this function either.

    std::cout << "\n\n Status: " << KeyAuthApp.response.message;


    std::cout << "\n\n Closing in five seconds...";
    Sleep(5000);

    return 0;
}

void sessionStatus() {
    KeyAuthApp.check(true); // do NOT specify true usually, it is slower and will get you blocked from API
    if (!KeyAuthApp.response.success) {
        exit(0);
    }

    if (KeyAuthApp.response.isPaid) {
        while (true) {
            Sleep(20000); // this MUST be included or else you get blocked from API
            KeyAuthApp.check();
            if (!KeyAuthApp.response.success) {
                exit(0);
            }
        }
    }
}
