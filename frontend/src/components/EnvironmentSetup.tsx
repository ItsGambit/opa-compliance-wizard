import { useMutation, useQueryClient } from '@tanstack/react-query'
import { saveEnvironment } from '../api/client'
import { toast } from '../hooks/useToast'
import type { ApiErrorBody, EnvironmentFormValues } from '../types'
import { EnvironmentForm } from './EnvironmentForm'

export function EnvironmentSetup() {
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: (values: EnvironmentFormValues) => saveEnvironment(values),
    onSuccess: (data) => {
      toast({ title: `Connected to '${data.active}'`, variant: 'success' })
      queryClient.invalidateQueries({ queryKey: ['environments'] })
    },
    onError: (err: Error) => toast({ title: 'Could not connect', description: err.message, variant: 'error' }),
  })

  const apiError = (mutation.error as (Error & { body?: ApiErrorBody }) | null)?.body?.error

  return (
    <div className="max-w-md mx-auto px-6 py-16 flex flex-col gap-5">
      <header>
        <h1 className="text-lg font-semibold text-text">Connect to Okta Privileged Access</h1>
        <p className="text-xs text-text-faint mt-1">
          No environment is configured yet. Enter your OPA service-user credentials to get started — you can add
          more environments (e.g. dev / uat / prod) later from the gear menu.
        </p>
      </header>
      <div className="card p-4">
        <EnvironmentForm
          submitLabel="Save & Connect"
          isSubmitting={mutation.isPending}
          errorMessage={apiError}
          onSubmit={values => mutation.mutate(values)}
        />
      </div>
    </div>
  )
}
