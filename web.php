  // Spatie roles Permissions routes
    Route::name('admin.')->group(function () {

        Route::resource('/roles', RoleController::class);
        Route::post('/roles/{role}/permissions/updateAll', [RoleController::class, 'updateAllPermissions'])
            ->name('roles.permissions.updateAll');

        Route::resource('/permissions', PermissionController::class);
        Route::post('/permissions/{permission}/roles', [PermissionController::class, 'assignRole'])->name('permissions.roles');
        Route::delete('/permissions/{permission}/roles/{role}', [PermissionController::class, 'removeRole'])->name('permissions.roles.remove');

        Route::get('/users', [UserRoleController::class, 'index'])->name('users.index');
        Route::get('/users/{user}', [UserRoleController::class, 'show'])->name('users.show');
        Route::delete('/users/{user}', [UserRoleController::class, 'destroy'])->name('users.destroy')->middleware('can:User-delete');

        Route::post('/role/{user}/assign/all', [UserRoleController::class, 'UserRoleUpdatedAll'])->name('user.role.updateAll');
        Route::post('/permissions/{user}/assign/all', [UserRoleController::class, 'UserPermissionUpdateAll'])->name('user.permissions.updateAll');
    });
