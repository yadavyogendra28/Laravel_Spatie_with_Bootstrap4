@extends('layouts.masterLayout')


@section('title','Index Role')

@section('content')

<div class="section-header">
    <h1>Manage Roles</h1>
</div>

<div class="py-1">
    <div class="container">
        <div class="card">
            <div class="card-header d-flex justify-content-end">
                <a href="{{ route('admin.roles.create') }}" class="btn btn-success">Create Role</a>
            </div>

            <div class="card-body">
                <div class="row">
                    @foreach ($roles as $role)
                    <div class="col-12 col-sm-6 col-md-4 col-lg-3 mb-4">
                        <div class="card shadow-sm border-0 h-100">
                            <div class="card-body d-flex flex-column justify-content-between">
                                <h5 class="card-title font-weight-bold">{{ $role->name }}</h5>
                                <p class="text-muted mb-0">Manage Role settings for this action.</p>

                                <div class="mt-3">
                                    <div class="btn-group" role="group" aria-label="Role Actions">
                                        <a href="{{ route('admin.roles.edit', $role->id) }}"
                                            class="btn btn-outline-primary btn-sm mr-1">Edit</a>
                                        <form method="POST" action="{{ route('admin.roles.destroy', $role->id) }}"
                                            onsubmit="return confirm('Are you sure?');" class="d-inline-block">
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
                </div>
            </div>

        </div>
    </div>
</div>


@endsection