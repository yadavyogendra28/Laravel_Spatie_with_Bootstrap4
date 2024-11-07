{{-- @extends('layouts.masterLayout')



@section('title','Permissions')

@section('content')

<div class="section-header">
    <h1>Permissions</h1>
</div>

<div class="py-12">
    <div class="container">
        <div class="card">
            <div class="card-header d-flex justify-content-end">
                <a href="{{ route('admin.permissions.create') }}" class="btn btn-success">Create Permission</a>
            </div>
            <div class="card-body">

                <div class="table-responsive shadow rounded p-3 ">
                    <table class="table table-striped table-hover" id="table-2">

                        <thead>
                            <tr>
                                <th>Name</th>
                                <th class="text-end"><span class="mx-5">Action</span></th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach ($permissions as $permission)
                            <tr>
                                <td class="px-6 py-4">{{ $permission->name }}</td>

                                <td class="text-end">
                                    <div class="btn-group" role="group" aria-label="Permission Actions">
                                        <a href="{{ route('admin.permissions.edit', $permission->id) }}"
                                            class="btn btn-primary mx-3">Edit</a>
                                        <form class="ml-2" method="POST"
                                            action="{{ route('admin.permissions.destroy', $permission->id) }}"
                                            onsubmit="return confirm('Are you sure?');">
                                            @csrf
                                            @method('DELETE')
                                            <button type="submit" class="btn btn-danger">Delete</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>


            </div>
        </div>
    </div>
</div>


@endsection --}}



@extends('layouts.masterLayout')

@section('title', 'Permissions')

@section('content')

<div class="section-header">
    <h1>Permissions</h1>
</div>

<div class="py-4">
    <div class="container">
        <div class="card">
            <div class="card-header d-flex justify-content-end">
                <a href="{{ route('admin.permissions.create') }}" class="btn btn-success">Create Permission</a>
            </div>


            @php
            $groupedPermissions = [];
            foreach ($permissions as $permission) {
            $permissionName = $permission->name;
            $selectedActions = explode('-', $permissionName);
            $modelName = array_shift($selectedActions);

            if (!isset($groupedPermissions[$modelName])) {
            $groupedPermissions[$modelName] = [];
            }
            $groupedPermissions[$modelName][] = $permission;
            }
            @endphp



            <div class="row">
                @foreach ($groupedPermissions as $modelName => $modelPermissions)
                <div class="col-12 mb-4">
                    <h6 class="font-weight-bold">{{ $modelName }} Permissions</h6>
                </div>

                @foreach ($modelPermissions as $permission)
                <div class="col-12 col-sm-6 col-md-4 col-lg-3 mb-4">
                    <div class="card shadow-sm border-0 h-100">
                        <div class="card-body d-flex flex-column justify-content-between">
                            <div>
                                <h5 class="card-title font-weight-bold">{{ $permission->name }}</h5>
                                <p class="text-muted mb-0">Manage permission settings for this action.</p>
                            </div>
                            <div class="mt-1">
                                <div class="btn-group" role="group" aria-label="Permission Actions">
                                    <a href="{{ route('admin.permissions.edit', $permission->id) }}"
                                        class="btn btn-outline-primary btn-sm mr-1">Edit</a>
                                    <form method="POST"
                                        action="{{ route('admin.permissions.destroy', $permission->id) }}"
                                        onsubmit="return confirm('Are you sure you want to delete this permission?');"
                                        class="d-inline-block">
                                        @csrf
                                        @method('DELETE')
                                        <button type="submit" class="btn btn-outline-danger btn-sm">Delete</button>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                @endforeach
                @endforeach
            </div>


        </div>
    </div>
</div>

@endsection